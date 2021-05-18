import datetime
from unittest.mock import MagicMock

import pytest
from mock import patch

from detect_secrets_stream.pi_cleaner.pi_cleaner import PICleaner
from detect_secrets_stream.scan_worker.commit import Commit
from detect_secrets_stream.scan_worker.secret import Secret


class TestPICleaner:

    email_domain = 'test.test'

    @pytest.fixture
    def test_pi_cleaner(self):
        pi_cleaner = PICleaner()

        pi_cleaner.get_db = mock_get_db = MagicMock()
        mock_get_db.return_value = mock_db_inst = MagicMock()

        return (pi_cleaner, mock_db_inst)

    @pytest.fixture
    def test_secret(self):
        secret = Secret('test_secret', 'secret_type')
        return secret

    @pytest.fixture
    def test_commit(self):
        commit = Commit('test_hash', 'test_repo', 'test_branch')
        return commit

    def test_remove_pi(self, test_pi_cleaner, test_secret, test_commit):
        pi_cleaner, mock_db_inst = test_pi_cleaner
        test_secret.live = False
        test_secret.id = 1
        test_secret.remediation_date = datetime.datetime(2018, 8, 25, 0, 0, 0, 0).astimezone(tz=datetime.timezone.utc)
        test_secret.owner_email = f'pi@{self.email_domain}'
        test_secret.secret = 'secret'
        test_secret.encrypted_secret = 'secret_enc'
        test_secret.other_factors = '{"another": "one"}'
        test_commit.author_name = 'author'
        test_commit.author_email = f'author@{self.email_domain}'
        test_commit.pusher_username = 'pusher'
        test_commit.pusher_email = f'pusher@{self.email_domain}'
        test_commit.committer_name = 'committer'
        test_commit.committer_email = f'committer@{self.email_domain}'
        test_commit.repo_slug = 'org/repo'
        test_commit.location_url = 'place/in/github'

        mock_db_inst.write_secret_to_db.return_value = True
        mock_db_inst.get_commits_by_token_id_from_db.return_value = [test_commit]

        result = pi_cleaner.remove_pi(test_secret)

        assert test_secret.is_pi_cleaned()
        assert result == (True, [], [])
        mock_db_inst.write_secret_to_db.assert_called_with(test_secret)
        mock_db_inst.get_commits_by_token_id_from_db.assert_called()
        mock_db_inst.update_commit_in_db.assert_called_with(test_commit)

    @patch('detect_secrets_stream.scan_worker.commit.Commit.is_pi_cleaned')
    @patch('detect_secrets_stream.scan_worker.secret.Secret.is_pi_cleaned')
    def test_remove_pi_fails_data_cleanliness(
        self, mock_secret_pi_cleaned, mock_commit_pi_cleaned, test_pi_cleaner, test_secret, test_commit,
    ):
        """ We still write it, just log an error. """
        pi_cleaner, mock_db_inst = test_pi_cleaner
        test_secret.live = False
        test_secret.id = 1
        test_secret.remediation_date = datetime.datetime(2018, 8, 25, 0, 0, 0, 0).astimezone(tz=datetime.timezone.utc)
        test_secret.owner_email = f'pi@{self.email_domain}'
        test_secret.secret = 'secret'
        test_secret.encrypted_secret = 'secret_enc'
        test_secret.other_factors = '{"another": "one"}'
        test_commit.author_name = 'author'
        test_commit.author_email = f'author@{self.email_domain}'
        test_commit.pusher_username = 'pusher'
        test_commit.pusher_email = f'pusher@{self.email_domain}'
        test_commit.committer_name = 'committer'
        test_commit.committer_email = f'committer@{self.email_domain}'
        test_commit.repo_slug = 'org/repo'
        test_commit.location_url = 'place/in/github'
        test_commit.commit_id = 1

        mock_secret_pi_cleaned.return_value = False
        mock_commit_pi_cleaned.return_value = False
        mock_db_inst.get_commits_by_token_id_from_db.return_value = [test_commit]

        result = pi_cleaner.remove_pi(test_secret)
        assert not test_secret.is_pi_cleaned()
        assert result == (False, [1], [1])
        mock_db_inst.write_secret_to_db.assert_called()
        mock_db_inst.get_commits_by_token_id_from_db.assert_called()
        mock_db_inst.update_commit_in_db.assert_called()

    def test_remove_pi_not_called(self, test_pi_cleaner, test_secret, test_commit):
        pi_cleaner, mock_db_inst = test_pi_cleaner
        test_secret.live = True
        test_secret.id = 1

        mock_db_inst.get_secret_from_db.return_value = test_secret

        result = pi_cleaner.remove_pi(test_secret)

        assert result == (True, [], [])
        # not called because token is live
        mock_db_inst.write_secret_to_db.assert_not_called()
        mock_db_inst.get_commits_by_token_id_from_db.assert_not_called()
        mock_db_inst.update_commit_in_db.assert_not_called()

    def test_remove_pi_not_called_2(self, test_pi_cleaner, test_secret, test_commit):
        pi_cleaner, mock_db_inst = test_pi_cleaner
        test_secret.live = False
        test_secret.id = 1
        test_secret.remediation_date = datetime.datetime.now().astimezone(tz=datetime.timezone.utc)

        result = pi_cleaner.remove_pi(test_secret)

        assert result == (True, [], [])
        # not called because the remediation date is not 7+ days ago
        mock_db_inst.write_secret_to_db.assert_not_called()
        mock_db_inst.get_commits_by_token_id_from_db.assert_not_called()
        mock_db_inst.update_commit_in_db.assert_not_called()

    def test_remove_pi_for_all_remediated_tokens(self, test_pi_cleaner, test_secret, test_commit):
        pi_cleaner, mock_db_inst = test_pi_cleaner
        token_ids = [1, 2]
        mock_db_inst.get_remediated_tokens_from_db.return_value = token_ids
        mock_db_inst.get_secret_from_db.return_value = test_secret
        mock_db_inst.get_commits_by_token_id_from_db.return_value = test_commit
        pi_cleaner.remove_pi = MagicMock()
        pi_cleaner.remove_pi.side_effect = [True, Exception('Fail to remove pi')]

        test_secret.secret = 'test-secret'
        test_secret.other_factors = '{"another": "one"}'
        test_secret.owner_email = f'test@{self.email_domain}'
        test_secret.encrypted_secret = 'test-secret-enc'

        pi_cleaner.remove_pi_for_all_remediated_tokens()

        pi_cleaner.remove_pi.assert_called()
        mock_db_inst.get_secret_from_db.assert_called()

    def test_remove_pi_for_all_remediated_tokens_not_called(self, test_pi_cleaner, test_secret, test_commit):
        pi_cleaner, mock_db_inst = test_pi_cleaner
        token_ids = [1, 2]
        mock_db_inst.get_remediated_tokens_from_db.return_value = token_ids
        mock_db_inst.get_secret_from_db.return_value = test_secret
        mock_db_inst.get_commits_by_token_id_from_db.return_value = test_commit
        pi_cleaner.remove_pi = MagicMock()
        pi_cleaner.remove_pi.side_effect = [True, Exception('Fail to remove pi')]

        test_secret.secret = ''
        test_secret.other_factors = ''
        test_secret.owner_email = ''
        test_secret.encrypted_secret = ''

        pi_cleaner.remove_pi_for_all_remediated_tokens()

        # not called because test secret has empty pi fields already
        pi_cleaner.remove_pi.assert_not_called()
        mock_db_inst.get_secret_from_db.assert_called()
