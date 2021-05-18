import csv
import datetime
import os
from unittest import TestCase

from mock import call
from mock import patch

from detect_secrets_stream.notification.gd_report_generator import GdReportGenerator
from detect_secrets_stream.scan_worker.secret import Secret
from detect_secrets_stream.security.security import DeterministicCryptor
from detect_secrets_stream.security.security import Encryptor


class TestGdReportGenerator(TestCase):

    @patch('detect_secrets_stream.notification.gd_report_generator.OrgSetController')
    @patch('detect_secrets_stream.notification.gd_report_generator.DbBiz')
    @patch('detect_secrets_stream.notification.gd_report_generator.connect_db')
    def setUp(self, mock_connect, mock_db, mock_org_set):
        self.mock_connect = mock_connect
        self.mock_db = mock_db
        self.mock_org_set = mock_org_set
        self.gd_report_generator = GdReportGenerator(include_security_focals=True, include_repo_visibility=True)
        self.encryptor = Encryptor()
        self.determ_encryptor = DeterministicCryptor()
        self.email_domain = 'test.test'
        self.mock_report_data = [
            [
                'test_token_id_1',
                'test_token_uuid_1',
                'test_raw_secret_enc_1',
                'test_owner_email_1',
                'test_location_url_enc_1',
                'test_repo_1',
                'test_filename_located_enc_1',
                'test_linenumber_located_enc_1',
                'test_commit_hash_enc_1',
                datetime.datetime.fromisoformat('2019-09-04T08:15:27-04:00'),
                'test_other_factors_enc_1',
                'test_token_type_1',
                'test_pusher_email_1',
                'test_committer_email_1',
                'test_author_email_1',
                datetime.datetime.fromisoformat('2019-09-05T08:15:27-04:00'),
                datetime.datetime.fromisoformat('2019-09-05T08:15:27-04:00'),
                True,  # is_live
                True,  # repo_public
                False,  # repo_private
            ],
            [
                'test_token_id_1',
                'test_token_uuid_1',
                'test_raw_secret_enc_1',
                'test_owner_email_1',
                'test_location_url_enc_1',
                'test_repo_1',
                'test_filename_located_enc_1',
                'test_linenumber_located_enc_1',
                'test_commit_hash_enc_1',
                datetime.datetime.fromisoformat('2019-10-04T08:15:27-04:00'),
                'test_other_factors_enc_1',
                'test_token_type_1',
                'test_pusher_email_1',
                'test_committer_email_1',
                'test_author_email_1',
                datetime.datetime.fromisoformat('2019-10-05T08:15:27-04:00'),
                datetime.datetime.fromisoformat('2019-10-05T08:15:27-04:00'),
                True,  # is_live
                False,  # repo_public
                True,  # repo_private
            ],
            [
                'test_token_id_2',
                'test_token_uuid_2',
                'test_raw_secret_enc_2',
                'test_owner_email_2',
                'test_location_url_enc_2',
                'test_repo_2',
                'test_filename_located_enc_2',
                'test_linenumber_located_enc_2',
                'test_commit_hash_enc_2',
                datetime.datetime.fromisoformat('2019-06-04T08:15:27-04:00'),
                'test_other_factors_enc_2',
                'test_token_type_2',
                'test_pusher_email_2',
                'test_committer_email_2',
                'test_author_email_2',
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                True,  # is_live
                False,  # repo_public
                True,  # repo_private
            ],
            [
                'test_token_id_3',
                'test_token_uuid_3',
                'test_raw_secret_enc_3',
                'test_owner_email_3',
                'test_location_url_enc_3',
                'test_repo_3',
                'test_filename_located_enc_3',
                'test_linenumber_located_enc_3',
                'test_commit_hash_enc_3',
                datetime.datetime.fromisoformat('2019-06-04T08:15:27-04:00'),
                'test_other_factors_enc_3',
                'IBM Cloud IAM Key',
                'test_pusher_email_3',
                'test_committer_email_3',
                'test_author_email_3',
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                True,  # is_live
                True,  # repo_public
                False,  # repo_private
            ],
            [
                'test_token_id_4',
                'test_token_uuid_4',
                'test_raw_secret_enc_4',
                'test_owner_email_4',
                'test_location_url_enc_4',
                'test_repo_4',
                'test_filename_located_enc_4',
                'test_linenumber_located_enc_4',
                'test_commit_hash_enc_4',
                datetime.datetime.fromisoformat('2019-06-04T08:15:27-04:00'),
                'test_other_factors_enc_4',
                'Slack Token',
                'test_pusher_email_4',
                'test_committer_email_4',
                'test_author_email_4',
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                True,  # is_live
                True,  # repo_public
                False,  # repo_private
            ],
            [
                'test_token_id_5',
                'test_token_uuid_5',
                'test_raw_secret_enc_5',
                'test_owner_email_5',
                'test_location_url_enc_5',
                'test_repo_5',
                'test_filename_located_enc_5',
                'test_linenumber_located_enc_5',
                'test_commit_hash_enc_5',
                datetime.datetime.fromisoformat('2019-06-04T08:15:27-04:00'),
                'test_other_factors_enc_5',
                'Slack Token',
                'test_pusher_email_5',
                'test_committer_email_5',
                'test_author_email_5',
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                datetime.datetime.fromisoformat('2019-06-05T08:15:27-04:00'),
                True,  # is_live
                True,  # repo_public
                False,  # repo_private
            ],
        ]
        self.fieldnames = [
            'Vuln Id',
            'Business Unit',
            'Token Owner Email',
            'Token type',
            'Vulnerability',
            'Action Required',
            'Pusher email',
            'Committer email',
            'Author email',
            'Date Last Tested',
            'Date Remediated',
            'Security Focals',
            'Repo Public',
            'Repo Private',
        ]

    def tearDown(self):
        if os.path.exists('./test.csv'):
            os.remove('./test.csv')

    def test_decode_hex_non_determ(self):
        text = 'this is some text'

        bytes_hex = self.encryptor.encrypt(text).hex()
        decrypted_text = self.gd_report_generator.decode_hex('\\x'+bytes_hex)
        assert decrypted_text == text

    def test_decode_hex_determ(self):
        text = 'this is some text'

        bytes_hex = self.determ_encryptor.encrypt(text).hex()
        decrypted_text = self.gd_report_generator.decode_hex('\\x'+bytes_hex)
        assert decrypted_text == text

    def test_decode_hex_raw(self):
        text = 'this is some text'
        decrypted_text = GdReportGenerator.decode_hex(text)
        assert decrypted_text == text

    def test_to_tz_str(self):
        timestamp = None
        result = ''
        timestamp_str = self.gd_report_generator.to_tz_str(timestamp)
        assert timestamp_str == result

        timestamp = datetime.datetime(2019, 9, 5, 9, 33, 16, 691259, tzinfo=datetime.timezone.utc)
        result = '2019-09-05T09:33:16+00:00'
        timestamp_str = self.gd_report_generator.to_tz_str(timestamp)
        assert timestamp_str == result

    @patch('detect_secrets_stream.notification.gd_report_generator.IBMCloudIAMValidator')
    @patch('detect_secrets_stream.notification.gd_report_generator.generate_report_recently_remediated')
    @patch('detect_secrets_stream.notification.gd_report_generator.generate_report_live_token')
    def test_generate_csv_from_db(self, mock_live_report, mock_remediated_report, mock_validator):
        mock_secret = Secret('test_raw_secret', 'test_type')
        mock_secret.other_factors = {'another': 'one'}
        mock_secret_iam = Secret('test-iam-secret', 'IBM Cloud IAM Key')
        mock_secret_slack_webhook = Secret('https://hooks.slack.com/services/secret', 'Slack Token')
        mock_secret_slack_token = Secret('xoxp-test-slack-secret', 'Slack Token')
        self.mock_db.return_value.get_secret_from_db.side_effect = [
            mock_secret, mock_secret, mock_secret_iam, mock_secret_slack_webhook,
            mock_secret_slack_token,
        ]
        mock_live_report.return_value = self.mock_report_data
        mock_remediated_report.return_value = self.mock_report_data

        mock_validator.return_value.get_service_id_uuid_and_name.return_value = ('123', 'george')
        mock_validator.return_value.get_service_id_apikey_meta.return_value = ({
            'id': 'ApiKey-11111111-1111-1111-1111-111111111111',
            'entity_tag': '<not sure the meaning of this field>',
            'crn': 'crn:v1:bluemix:public:iam-identity::a/xxxxxxx::apikey:xxxx',
            'locked': False,
            'created_at': '2019-01-03T10:07+0000',
            'modified_at': '2019-01-03T10:07+0000',
            'name': 'auto-generated-apikey-11111111-1111-1111-1111-1111111111111',
            'description': 'a good description of what this key is',
            'iam_id': '<iam_id>',
            'account_id': '<account_id>',
            'apikey': '<raw_apikey>',
        })
        self.mock_org_set.return_value.get_org_set_names_for_repo.return_value = 'test-org-set'
        self.mock_org_set.return_value.get_security_focal_emails_for_repo.return_value = [
            f'test-admin@{self.email_domain}', f'another-admin@us.{self.email_domain}',
        ]
        self.gd_report_generator.generate_csv_from_db('./test.csv', 'test-org-set')

        actual_results = []
        with open('./test.csv') as csvfile:
            reader = csv.reader(csvfile)
            first_row = next(reader)
            assert first_row == self.fieldnames
            for row in reader:
                actual_results.append(row)

        vulnerability_1 = """Last 5 characters of token: ecret

Token Owner Email: test_owner_email_1
HTML file URL: test_location_url_enc_1
Repo: test_repo_1
Filename: test_filename_located_enc_1
Line found: test_linenumber_located_enc_1
Commit Hash: test_commit_hash_enc_1
Date found: 2019-09-04T12:15:27+00:00
Number of commits discovered in: 4
Notes: other factors {'another': 'one'}"""

        vulnerability_2 = """Last 5 characters of token: ecret

Token Owner Email: test_owner_email_2
HTML file URL: test_location_url_enc_2
Repo: test_repo_2
Filename: test_filename_located_enc_2
Line found: test_linenumber_located_enc_2
Commit Hash: test_commit_hash_enc_2
Date found: 2019-06-04T12:15:27+00:00
Number of commits discovered in: 2
Notes: other factors {'another': 'one'}"""

        iam_meta = """IBM Cloud IAM KEY Service ID metadata: {\
'id': 'ApiKey-11111111-1111-1111-1111-111111111111', \
'crn': 'crn:v1:bluemix:public:iam-identity::a/xxxxxxx::apikey:xxxx', \
'created_at': '2019-01-03T10:07+0000', \
'name': 'auto-generated-apikey-11111111-1111-1111-1111-1111111111111', \
'description': 'a good description of what this key is', 'iam_id': '<iam_id>', \
'account_id': '<account_id>'}"""

        vulnerability_3 = """Last 5 characters of token: ecret

Token Owner Email: test_owner_email_3
HTML file URL: test_location_url_enc_3
Repo: test_repo_3
Filename: test_filename_located_enc_3
Line found: test_linenumber_located_enc_3
Commit Hash: test_commit_hash_enc_3
Date found: 2019-06-04T12:15:27+00:00
Number of commits discovered in: 2
IBM Cloud IAM Service ID UUID: 123
IBM Cloud IAM Service ID Name: george
""" + iam_meta

        vulnerability_4 = """Last 5 characters of token: ecret

Token Owner Email: test_owner_email_4
HTML file URL: test_location_url_enc_4
Repo: test_repo_4
Filename: test_filename_located_enc_4
Line found: test_linenumber_located_enc_4
Commit Hash: test_commit_hash_enc_4
Date found: 2019-06-04T12:15:27+00:00
Number of commits discovered in: 2"""

        vulnerability_5 = """Last 5 characters of token: ecret

Token Owner Email: test_owner_email_5
HTML file URL: test_location_url_enc_5
Repo: test_repo_5
Filename: test_filename_located_enc_5
Line found: test_linenumber_located_enc_5
Commit Hash: test_commit_hash_enc_5
Date found: 2019-06-04T12:15:27+00:00
Number of commits discovered in: 2"""

        expected_results = [
            [
                'test_token_uuid_1',
                '',  # business unit
                'test_owner_email_1',
                'test_token_type_1',
                vulnerability_1,
                '',  # action required
                'test_pusher_email_1',
                'test_committer_email_1',
                'test_author_email_1',
                '2019-09-05T12:15:27+00:00',
                '2019-09-05T12:15:27+00:00',
                f'test-admin@{self.email_domain},another-admin@us.{self.email_domain}',
                'True',
                'True',
            ],
            [
                'test_token_uuid_2',
                '',  # business unit
                'test_owner_email_2',
                'test_token_type_2',
                vulnerability_2,
                '',  # action required
                'test_pusher_email_2',
                'test_committer_email_2',
                'test_author_email_2',
                '2019-06-05T12:15:27+00:00',
                '2019-06-05T12:15:27+00:00',
                f'test-admin@{self.email_domain},another-admin@us.{self.email_domain}',
                'False',
                'True',
            ],
            [
                'test_token_uuid_3',
                '',  # business unit
                'test_owner_email_3',
                'IBM Cloud IAM Key',
                vulnerability_3,
                '',  # action required
                'test_pusher_email_3',
                'test_committer_email_3',
                'test_author_email_3',
                '2019-06-05T12:15:27+00:00',
                '2019-06-05T12:15:27+00:00',
                f'test-admin@{self.email_domain},another-admin@us.{self.email_domain}',
                'True',
                'False',
            ],
            [
                'test_token_uuid_4',
                '',  # business unit
                'test_owner_email_4',
                'Slack Webhook',
                vulnerability_4,
                '',  # action required
                'test_pusher_email_4',
                'test_committer_email_4',
                'test_author_email_4',
                '2019-06-05T12:15:27+00:00',
                '2019-06-05T12:15:27+00:00',
                f'test-admin@{self.email_domain},another-admin@us.{self.email_domain}',
                'True',
                'False',
            ],
            [
                'test_token_uuid_5',
                '',  # business unit
                'test_owner_email_5',
                'Slack Token',
                vulnerability_5,
                '',  # action required
                'test_pusher_email_5',
                'test_committer_email_5',
                'test_author_email_5',
                '2019-06-05T12:15:27+00:00',
                '2019-06-05T12:15:27+00:00',
                f'test-admin@{self.email_domain},another-admin@us.{self.email_domain}',
                'True',
                'False',
            ],
        ]

        for i in range(len(expected_results)):
            result = expected_results[i]
            actual_result = actual_results[i]
            for i in range(len(result)):
                assert result[i] == actual_result[i]

    @patch('detect_secrets_stream.notification.gd_report_generator.IBMCloudIAMValidator')
    @patch('detect_secrets_stream.notification.gd_report_generator.write_vmt_report')
    @patch('detect_secrets_stream.notification.gd_report_generator.generate_report_recently_remediated')
    @patch('detect_secrets_stream.notification.gd_report_generator.generate_report_live_token')
    def test_generate_vmt_report_in_db(self, mock_live_report, mock_remediated_report, mock_write, mock_validator):
        mock_secret = Secret('test_raw_secret', 'test_type')
        mock_secret.other_factors = {'another': 'one'}
        mock_validator.return_value.get_service_id_uuid_and_name.return_value = '123', 'abcde'
        self.mock_db.return_value.get_secret_from_db.return_value = mock_secret
        mock_live_report.return_value = self.mock_report_data
        mock_remediated_report.return_value = self.mock_report_data
        self.mock_org_set.return_value.get_org_set_names_for_repo.return_value = 'test-org-set'
        self.mock_org_set.return_value.get_security_focal_emails_for_repo.return_value = [
            f'test-admin@{self.email_domain}', f'another-admin@us.{self.email_domain}',
        ]
        self.gd_report_generator.generate_vmt_report_in_db('test-org-set')

        vulnerability_1 = """Last 5 characters of token: ecret

Token Owner Email: test_owner_email_1
HTML file URL: test_location_url_enc_1
Repo: test_repo_1
Filename: test_filename_located_enc_1
Line found: test_linenumber_located_enc_1
Commit Hash: test_commit_hash_enc_1
Date found: 2019-09-04T12:15:27+00:00
Number of commits discovered in: 4
Notes: other factors {'another': 'one'}"""

        vulnerability_2 = """Last 5 characters of token: ecret

Token Owner Email: test_owner_email_2
HTML file URL: test_location_url_enc_2
Repo: test_repo_2
Filename: test_filename_located_enc_2
Line found: test_linenumber_located_enc_2
Commit Hash: test_commit_hash_enc_2
Date found: 2019-06-04T12:15:27+00:00
Number of commits discovered in: 2
Notes: other factors {'another': 'one'}"""

        calls = [
            call(
                self.gd_report_generator.conn,
                'test_token_uuid_1',
                'test_owner_email_1',
                'test_token_type_1',
                vulnerability_1,
                'test_pusher_email_1',
                'test_committer_email_1',
                'test_author_email_1',
                '2019-09-05T12:15:27+00:00',
                '2019-09-05T12:15:27+00:00',
                f'test-admin@{self.email_domain},another-admin@us.{self.email_domain}',
                True,
                True,
            ),
            call(
                self.gd_report_generator.conn,
                'test_token_uuid_2',
                'test_owner_email_2',
                'test_token_type_2',
                vulnerability_2,
                'test_pusher_email_2',
                'test_committer_email_2',
                'test_author_email_2',
                '2019-06-05T12:15:27+00:00',
                '2019-06-05T12:15:27+00:00',
                f'test-admin@{self.email_domain},another-admin@us.{self.email_domain}',
                False,
                True,
            ),
        ]
        mock_write.assert_has_calls(calls, any_order=True)
