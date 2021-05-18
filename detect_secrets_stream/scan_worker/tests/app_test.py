import asyncio
import os
from unittest import TestCase
from unittest.mock import patch

import pytest

from detect_secrets_stream.scan_worker.app import EventStreamsApp


class AppTest (TestCase):

    @patch('detect_secrets_stream.util.conf.ConfUtil.load_kafka_conf')
    def setUp(self, mock_load_kafka_conf):
        os.environ['KAFKA_CLIENT_ID'] = 'test_client_id'
        os.environ['KAFKA_GROUP_ID'] = 'test_group_id'
        self.test_diff_topic = 'diff-scan-test'
        self.test_notification_topic = 'notification-test'
        mock_kafka_config = {}
        mock_kafka_config['brokers_sasl'] = 'broker1.com, broker2.com, broker3.com'
        mock_kafka_config['api_key'] = 'someRandomTestKey'
        mock_load_kafka_conf.return_value = mock_kafka_config
        self.app = EventStreamsApp(
            self.test_diff_topic, self.test_notification_topic, async_sleep_time=0.1,
        )

    def test_run_tasks_and_shutdown(self):
        loop = asyncio.get_event_loop()
        loop.call_later(0.1, self.app.shutdown, 'test_signal', 'test_frame')
        with pytest.raises(SystemExit):
            loop.run_until_complete(self.app.run_tasks())

        self.assertFalse(self.app.diff_scan_worker.running)
