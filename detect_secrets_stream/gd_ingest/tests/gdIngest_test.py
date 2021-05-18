import logging
import unittest

from detect_secrets_stream.gd_ingest.gd_ingest import GDIngest


class GDIngstTestcases(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(GDIngstTestcases, self).__init__(*args, **kwargs)

    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger('gdingesttests')
        if not cls.logger.handlers:
            cls.logger.setLevel(logging.DEBUG)
            cls.handler = logging.StreamHandler()
            cls.handler.setFormatter(
                logging.Formatter(
                    '[%(asctime)-15s] [%(module)s] %(levelname)s %(message)s',
                ),
            )
            cls.logger.addHandler(cls.handler)
        cls.logger.info('Setting up class...')

        cls.kafka_config = {
            'client.id': 'gd-ingest',
            'bootstrap.servers': ['broker1.com', 'broker2.com', 'broker3.com'],
            'security.protocol': 'SASL_SSL',
            'sasl.mechanisms': 'PLAIN',
            'sasl.username': 'saslUser',
            'sasl.password': 'someRandomTestKey',
            'api.version.request': True,
            'broker.version.fallback': '0.10.2.1',
            'log.connection.close': False,
        }
        cls.gd_ingest = None

    @classmethod
    def tearDownClass(cls):
        cls.logger.info('Tearing down class...')

    def setUp(self):
        self.logger.info('--- [Begin] %s ---' % (self.shortDescription()))

    def tearDown(self):
        self.logger.info('--- [End] %s ---' % (self.shortDescription()))

    def test_constructor(self):
        """ [GDIngest] Constructor """
        gd_ingest = GDIngest(self.kafka_config)
        self.assertIsInstance(gd_ingest, GDIngest)
        self.__class__.gd_ingest = gd_ingest


if __name__ == '__main__':
    results = unittest.main()
