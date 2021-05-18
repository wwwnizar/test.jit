#!/usr/bin/python
##############################################################################################
#
# IBM Confidential
#
# OCO Source Materials
#
#
# (c) Copyright IBM Corp. 2019
# The source code for this program is not published or other-
# wise divested of its trade secrets, irrespective of what has
# been deposited with the U.S. Copyright Office.
##############################################################################################
import logging
import os
import random

from confluent_kafka import Producer
from jaeger_client import Config
from jaeger_client.metrics.prometheus import PrometheusMetricsFactory


class GDIngest(object):

    def __init__(self, kafka_config):
        self.logger = logging.getLogger(__name__)
        self.__producer = Producer(kafka_config)

        self.__rollout_percentage = int(
            os.getenv('ROLLOUT_PERCENTAGE', default='100'),
        )

    def init_tracer(self, service_name='detect_secrets'):
        config = Config(
            config={  # usually read from some yaml config
                'sampler': {
                    'type': 'const',
                    'param': 1,
                },
                'logging': True,
            },
            service_name=service_name,
            validate=True,
            metrics_factory=PrometheusMetricsFactory(namespace=service_name),
        )
        return config.initialize_tracer()

    def on_delivery(self, err, msg):
        if err:
            self.logger.error(
                'Delivery report: Failed sending message {0}'.format(
                    msg.value(),
                ), extra={'error': err},
            )
            # We could retry sending the message
        else:
            self.logger.info(
                'Message produced, offset: {0}'.format(msg.offset()),
            )

    def add_message_to_queue(self, topic_name, message, key=None):

        self.logger.info(
            'About to process message based on rollout percentage',
        )
        # randomly process ROLLOUT_PERCENTAGE of commits
        random_number = random.randint(1, 101)
        process_commit = random_number % 100 <= self.__rollout_percentage
        if process_commit:
            self.logger.info('accept message')
            try:
                # Use default round robin by not supplying a key
                self.__producer.produce(
                    topic_name, message, key=key, partition=-1, on_delivery=self.on_delivery,
                )
                self.__producer.poll(0)
            except Exception:
                self.logger.error(
                    'Failed sending message {0}'.format(message), exc_info=1,
                )
            finally:
                self.__producer.flush()
        else:
            self.logger.info('drop message due to rollout percentage')
