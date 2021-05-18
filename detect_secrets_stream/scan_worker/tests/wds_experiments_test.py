import json
import os
from unittest import TestCase

from mock import call
from mock import patch

from detect_secrets_stream.scan_worker.wds_experiments import WDSExperiments


class WDSExperimentsTest (TestCase):

    def setUp(self):
        self.wds_experiments = WDSExperiments()
        # test-type-1 has 1 true positive, 2 false positives
        # test-type-2 has 2 true positives, 1 false positive
        self.test_ds_results = json.dumps({
            'results': {
                'test-file.test': [
                    {
                        'type': 'test-type-1',
                        'is_verified': True,
                        'verified_result': True,
                    },
                    {
                        'type': 'not-test-type',
                        'is_verified': True,
                        'verified_result': True,
                    },
                ],
                'test-file-2.tst': [
                    {
                        'type': 'test-type-1',
                        'is_verified': True,
                        'verified_result': None,
                    },
                    {
                        'type': 'test-type-2',
                        'is_verified': True,
                        'verified_result': False,
                    },
                    {
                        'type': 'test-type-1',
                        'is_verified': True,
                        'verified_result': False,
                    },
                ],
                'test-file-3.testy': [
                    {
                        'type': 'test-type-2',
                        'is_verified': True,
                        'verified_result': True,
                    },
                    {
                        'type': 'test-type-2',
                        'is_verified': True,
                        'verified_result': True,
                    },
                ],
            },
        })
        self.diff_filename = 'test-diff.test'
        self.test_repo_slug = 'test-owner/test-repo'
        self.test_commit_hash = '0000000000'

    def tearDown(self):
        if os.path.exists(self.diff_filename):
            os.remove(self.diff_filename)

    def test_run_detect_secrets_github(self):
        fake_gh_token = 'abcd1234abcd1234abcd1234abcd1234abcd1234'  # pragma: whitelist secret
        with open(self.diff_filename, 'w') as diff_file:
            diff_file.write(f'token={fake_gh_token}')
        ds_output = json.loads(self.wds_experiments.run_detect_secrets(self.diff_filename))
        self.assertIn(self.diff_filename, ds_output['results'])
        self.assertIn(
            fake_gh_token, [
                secret['secret'] for secret in ds_output['results'][self.diff_filename]
            ],
        )
        self.assertIn(
            'GitHub Credentials', [
                secret['type'] for secret in ds_output['results'][self.diff_filename]
            ],
        )
        self.assertIn(
            1, [
                secret['line_number']
                for secret in ds_output['results'][self.diff_filename]
            ],
        )

    @patch('detect_secrets_stream.scan_worker.wds_experiments.WDSExperiments.output_string')
    def test_print_results(self, mock_output):
        self.wds_experiments.print_results(
            self.test_ds_results, 'test-type-1',
            self.test_repo_slug, self.test_commit_hash,
        )
        mock_output.assert_called_with(
            '{"repo_slug": "test-owner/test-repo", "commit_hash": "0000000000",'
            ' "secret_type": "test-type-1", "false_positives": 2, "true_positives": 1}',
        )

    @patch('detect_secrets_stream.scan_worker.wds_experiments.WDSExperiments.output_string')
    @patch('detect_secrets_stream.scan_worker.wds_experiments.WDSExperiments.run_detect_secrets')
    def test_evaluate_detector(self, mock_ds, mock_output):
        mock_ds.return_value = self.test_ds_results
        self.wds_experiments.evaluate_detector(
            self.diff_filename, 'test-type-2',
            self.test_repo_slug, self.test_commit_hash,
        )
        mock_ds.assert_called_with(self.diff_filename)
        mock_output.assert_called_with(
            '{"repo_slug": "test-owner/test-repo", "commit_hash": "0000000000",'
            ' "secret_type": "test-type-2", "false_positives": 1, "true_positives": 2}',
        )

    @patch('detect_secrets_stream.scan_worker.wds_experiments.WDSExperiments.output_string')
    @patch('detect_secrets_stream.scan_worker.wds_experiments.WDSExperiments.run_detect_secrets')
    def test_compare_detectors(self, mock_ds, mock_output):
        mock_ds.return_value = self.test_ds_results
        self.wds_experiments.compare_detectors(
            self.diff_filename, 'test-type-1', 'test-type-2',
            self.test_repo_slug, self.test_commit_hash,
        )
        mock_ds.assert_called_with(self.diff_filename)
        calls = [
            call(
                '{"repo_slug": "test-owner/test-repo", "commit_hash": "0000000000",'
                ' "secret_type": "test-type-1", "false_positives": 2, "true_positives": 1}',
            ),
            call(
                '{"repo_slug": "test-owner/test-repo", "commit_hash": "0000000000",'
                ' "secret_type": "test-type-2", "false_positives": 1, "true_positives": 2}',
            ),
        ]
        mock_output.assert_has_calls(calls)
