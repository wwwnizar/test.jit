from datetime import datetime
from datetime import timezone
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from detect_secrets_stream.scan_worker.secret import Secret
from detect_secrets_stream.secret_corpus_db.db_biz import DbBiz
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_token_count
from detect_secrets_stream.secret_corpus_db.vault_read_exception import VaultReadException


class TestDbBiz:

    @pytest.fixture
    def test_secret(self):
        secret_cred = 'Secret Cred'
        secret = Secret(secret_cred, 'Secret Type')
        assert secret.id is None
        secret.other_factors = {'something': 'another thing'}
        secret.comment = 'some comments'
        secret.filename = 'filename'
        secret.linenumber = 'linenumber'
        secret.owner_email = 'owner@email.com'
        return secret

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    def test_get_secret_wrong_input(self, mock_vault):
        db = DbBiz()
        secret = db.get_secret_from_db(None)
        assert secret is None

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    @patch('detect_secrets_stream.secret_corpus_db.db_biz.get_token_by_id')
    def test_get_secret_not_existed(self, mock_get_token, mock_vault):
        db = DbBiz()
        db.get_conn = MagicMock()
        mock_get_token.return_value = MagicMock()
        mock_get_token.return_value = []

        secret = db.get_secret_from_db('does not existed')

        assert secret is None
        mock_get_token.assert_called()

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    @patch('detect_secrets_stream.secret_corpus_db.db_biz.get_token_by_id')
    def test_get_secret_not_in_vault(self, mock_get_token, mock_vault):
        token_id = '123'
        db = DbBiz()
        db.get_conn = MagicMock()
        mock_get_token.return_value = MagicMock()
        mock_get_token.return_value = [
            (
                token_id,
                memoryview(b'token_cred_enc'),
                'token_comment',
                'token_type',
                'first_identified',
                'is_live',
                'last_test_date',
                'last_test_success',
                'token_hash',
                memoryview(b'other_factors_enc'),
                'uuid',
                'owner_email',
                'remediation_date',
            ),
        ]

        def decrypt_side_effect(value):
            if value == b'token_cred_enc':
                return 'token_cred'
            elif value == b'other_factors_enc':
                return 'other_factors'
            else:
                return ''
        db.decrypt = MagicMock()
        db.decrypt.side_effect = decrypt_side_effect
        mock_vault.return_value.read_secret.side_effect = VaultReadException('secret not in vault or id not set')

        secret = db.get_secret_from_db('not in vault')

        mock_get_token.assert_called()
        mock_vault.assert_called()
        assert secret is not None
        assert secret.id == token_id
        assert secret.encrypted_secret == b'token_cred_enc'
        assert secret.secret == 'token_cred'
        assert secret.comment == 'token_comment'
        assert secret.secret_type == 'token_type'
        assert secret.first_identified == 'first_identified'
        assert secret.live == 'is_live'
        assert secret.last_test_date == 'last_test_date'
        assert secret.last_test_success == 'last_test_success'
        assert secret.hashed_secret == 'token_hash'
        assert secret.encrypted_other_factors == b'other_factors_enc'
        assert secret.other_factors == 'other_factors'
        assert secret.uuid == 'uuid'
        assert secret.owner_email == 'owner_email'
        assert secret.remediation_date == 'remediation_date'

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    @patch('detect_secrets_stream.secret_corpus_db.db_biz.get_token_by_id')
    def test_get_secret_normal(self, mock_get_token, mock_vault):
        token_id = '123'
        db = DbBiz()
        db.get_conn = MagicMock()
        mock_get_token.return_value = MagicMock()
        mock_get_token.return_value = [
            (
                token_id,
                memoryview(b'token_cred_enc'),
                'token_comment',
                'token_type',
                'first_identified',
                'is_live',
                'last_test_date',
                'last_test_success',
                'token_hash',
                memoryview(b'other_factors_enc'),
                'uuid',
                'owner_email',
                'remediation_date',
            ),
        ]

        def decrypt_side_effect(value):
            if value == b'token_cred_enc':
                return 'some_token_cred'
            elif value == b'other_factors_enc':
                return 'some_other_factors'
            else:
                return ''
        db.decrypt = MagicMock()
        db.decrypt.side_effect = decrypt_side_effect
        mock_vault.return_value.read_secret.return_value = {'secret': 'token_cred', 'other_factors': 'other_factors'}

        secret = db.get_secret_from_db(token_id)

        mock_get_token.assert_called()
        mock_vault.assert_called()
        assert secret is not None
        assert secret.id == token_id
        assert secret.encrypted_secret == b'token_cred_enc'
        assert secret.secret == 'token_cred'
        assert secret.comment == 'token_comment'
        assert secret.secret_type == 'token_type'
        assert secret.first_identified == 'first_identified'
        assert secret.live == 'is_live'
        assert secret.last_test_date == 'last_test_date'
        assert secret.last_test_success == 'last_test_success'
        assert secret.hashed_secret == 'token_hash'
        assert secret.encrypted_other_factors == b'other_factors_enc'
        assert secret.other_factors == 'other_factors'
        assert secret.uuid == 'uuid'
        assert secret.owner_email == 'owner_email'
        assert secret.remediation_date == 'remediation_date'

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.DeterministicCryptor')
    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    @patch('detect_secrets_stream.secret_corpus_db.db_biz.get_commits_by_token_id')
    def test_get_commits_by_token_id(self, mock_get_commits, mock_vault, mock_decrypter):
        token_id = '123'
        db = DbBiz()
        db.get_conn = MagicMock()
        mock_get_commits.return_value = [
            (
                '1',
                memoryview(b'commit_hash_enc'),
                'repo_slug',
                memoryview(b'branch_name_enc'),
                memoryview(b'location_url_enc'),
                'author_name',
                'author_email',
                'pusher_username',
                'pusher_email',
                'committer_name',
                'committer_email',
                True,  # repo_public
                'uniqueness_hash',
                memoryview(b'filename_enc'),
                memoryview(b'linenumber_enc'),
                123,  # token_id
            ),
            (
                '2',
                memoryview(b'commit_hash_enc'),
                'repo_slug',
                memoryview(b'branch_name_enc'),
                memoryview(b'location_url_enc'),
                'author_name',
                'author_email',
                'pusher_username',
                'pusher_email',
                'committer_name',
                'committer_email',
                False,  # repo_public
                'uniqueness_hash',
                memoryview(b'filename_enc'),
                memoryview(b'linenumber_enc'),
                123,  # token_id
            ),
        ]
        mock_decrypter.return_value.decrypt.side_effect = [
            'commit_hash', 'branch_name', 'location_url', 'filename', 1,
            'commit_hash', 'branch_name', 'location_url', 'filename', 1,
        ]

        def decrypt_side_effect(value):
            if value == b'commit_hash_enc':
                return 'commit_hash'
            elif value == b'branch_name_enc':
                return 'branch_name'
            elif value == b'location_url_enc':
                return 'location_url'
            elif value == b'filename_enc':
                return 'filename'
            elif value == b'linenumber_enc':
                return 1
            else:
                return ''
        db.decrypt = MagicMock()
        db.decrypt.side_effect = decrypt_side_effect
        commits = db.get_commits_by_token_id_from_db(token_id)
        mock_get_commits.assert_called()
        assert commits[0] is not None
        assert commits[0].commit_id == 1
        assert commits[0].commit_hash == 'commit_hash'
        assert commits[0].repo_slug == 'repo_slug'
        assert commits[0].branch_name == 'branch_name'
        assert commits[0].location_url == 'location_url'
        assert commits[0].author_name == 'author_name'
        assert commits[0].author_email == 'author_email'
        assert commits[0].pusher_username == 'pusher_username'
        assert commits[0].pusher_email == 'pusher_email'
        assert commits[0].committer_name == 'committer_name'
        assert commits[0].committer_email == 'committer_email'
        assert commits[0].repo_public is True
        assert commits[0].uniqueness_hash == 'uniqueness_hash'
        assert commits[0].filename == 'filename'
        assert commits[0].linenumber == 1
        assert commits[0].token_id == 123
        assert commits[0].encrypted_location_url is not None
        assert commits[0].encrypted_commit_hash is not None
        assert commits[0].encrypted_branch_name is not None
        assert commits[0].encrypted_filename is not None
        assert commits[0].encrypted_linenumber is not None

        assert commits[1] is not None
        assert commits[1].commit_id == 2
        assert commits[1].commit_hash == 'commit_hash'
        assert commits[1].repo_slug == 'repo_slug'
        assert commits[1].branch_name == 'branch_name'
        assert commits[1].location_url == 'location_url'
        assert commits[1].author_name == 'author_name'
        assert commits[1].author_email == 'author_email'
        assert commits[1].pusher_username == 'pusher_username'
        assert commits[1].pusher_email == 'pusher_email'
        assert commits[1].committer_name == 'committer_name'
        assert commits[1].committer_email == 'committer_email'
        assert commits[1].repo_public is False
        assert commits[1].uniqueness_hash == 'uniqueness_hash'
        assert commits[1].filename == 'filename'
        assert commits[1].linenumber == 1
        assert commits[1].token_id == 123
        assert commits[1].encrypted_location_url is not None
        assert commits[1].encrypted_commit_hash is not None
        assert commits[1].encrypted_branch_name is not None
        assert commits[1].encrypted_filename is not None
        assert commits[1].encrypted_linenumber is not None

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    @patch('detect_secrets_stream.secret_corpus_db.db_biz.get_commits_by_token_id')
    def test_get_commits_by_token_id_no_results(self, mock_get_commits, mock_vault):
        token_id = '123'
        db = DbBiz()
        db.get_conn = MagicMock()
        mock_get_commits.return_value = []

        commits = db.get_commits_by_token_id_from_db(token_id)
        mock_get_commits.assert_called()
        assert len(commits) == 0

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    def test_insert_increase_count_integration(self, mock_vault, database_with_data):
        old_count = _get_token_count(database_with_data)
        secret = Secret('Secret Cred', 'Secret Type')
        assert secret.id is None

        db = DbBiz()
        db.conn = database_with_data

        new_secret_id = db.write_secret_to_db(secret)
        assert new_secret_id is not None

        new_count = _get_token_count(database_with_data)
        assert new_count == 1 + old_count
        mock_vault.assert_called()

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    def test_insert_default_value_integration(self, mock_vault, database_with_data):
        secret_cred = 'Secret Cred'
        secret = Secret(secret_cred, 'Secret Type')
        assert secret.id is None

        db = DbBiz()
        db.conn = database_with_data

        new_secret_id = db.write_secret_to_db(secret)
        assert new_secret_id is not None

        mock_vault.return_value.read_secret.return_value = {'secret': 'Secret Cred', 'other_factors': {}}
        return_secret = db.get_secret_from_db(new_secret_id)

        assert return_secret.id == new_secret_id

        assert return_secret.secret == secret.secret
        assert return_secret.secret == secret_cred
        assert return_secret.encrypted_secret != secret.encrypted_secret
        assert type(return_secret.encrypted_secret) is bytes

        assert return_secret.comment == secret.comment
        assert return_secret.comment is None

        assert return_secret.first_identified != secret.first_identified
        assert type(return_secret.first_identified) is datetime
        assert return_secret.first_identified is not None
        assert secret.first_identified is None

        assert return_secret.live == secret.live
        assert return_secret.live is None

        assert return_secret.last_test_date == secret.last_test_date
        assert return_secret.last_test_date is None

        assert return_secret.last_test_success == secret.last_test_success
        assert return_secret.last_test_success is None

        assert return_secret.hashed_secret == secret.hashed_secret
        assert return_secret.hashed_secret is not None

        assert return_secret.other_factors is None
        assert secret.other_factors is None

        assert return_secret.encrypted_other_factors == secret.encrypted_other_factors
        assert return_secret.encrypted_other_factors is None

        assert return_secret.uuid == secret.uuid
        assert type(return_secret.uuid) is str
        assert return_secret.uuid is not None

        assert return_secret.owner_email == secret.owner_email
        assert return_secret.owner_email is None

        assert return_secret.remediation_date == secret.remediation_date
        assert return_secret.remediation_date is None

        mock_vault.assert_called()

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    def test_insert_customized_value_integration(self, mock_vault, database_with_data, test_secret):
        secret = test_secret
        secret_cred = test_secret.secret

        db = DbBiz()
        db.conn = database_with_data

        new_secret_id = db.write_secret_to_db(secret)
        assert new_secret_id is not None

        mock_vault.return_value.read_secret.return_value = {
            'secret': 'Secret Cred', 'other_factors': {'something': 'another thing'},
        }
        return_secret = db.get_secret_from_db(new_secret_id)

        assert return_secret.id == new_secret_id

        assert return_secret.secret == secret.secret
        assert return_secret.secret == secret_cred
        assert return_secret.encrypted_secret != secret.encrypted_secret
        assert type(return_secret.encrypted_secret) is bytes

        assert return_secret.comment == secret.comment
        assert return_secret.comment is not None

        assert return_secret.first_identified != secret.first_identified
        assert type(return_secret.first_identified) is datetime
        assert return_secret.first_identified is not None
        assert secret.first_identified is None

        assert return_secret.live == secret.live
        assert return_secret.live is None

        assert return_secret.last_test_date == secret.last_test_date
        assert return_secret.last_test_date is None

        assert return_secret.last_test_success == secret.last_test_success
        assert return_secret.last_test_success is None

        assert return_secret.hashed_secret == secret.hashed_secret
        assert return_secret.hashed_secret is not None

        assert return_secret.other_factors == secret.other_factors
        assert return_secret.other_factors is not None

        assert return_secret.encrypted_other_factors != secret.encrypted_other_factors
        assert return_secret.encrypted_other_factors is not None

        assert return_secret.uuid == secret.uuid
        assert type(return_secret.uuid) is str
        assert return_secret.uuid is not None

        assert return_secret.owner_email == secret.owner_email
        assert return_secret.owner_email is not None

        assert return_secret.remediation_date == secret.remediation_date
        assert return_secret.remediation_date is None

        mock_vault.assert_called()

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    def test_query_update_query_integration(self, mock_vault, database_with_data, test_secret):
        db = DbBiz()
        db.conn = database_with_data

        # insert one entry into DB
        token_id = db.write_secret_to_db(test_secret)

        # query
        mock_vault.return_value.read_secret.return_value = {
            'secret': 'Secret Cred', 'other_factors': {'something': 'another thing'},
        }
        secret = db.get_secret_from_db(token_id)

        # update
        write_secret_id = db.write_secret_to_db(secret)
        assert write_secret_id is not None
        assert write_secret_id == token_id

        # query
        return_secret = db.get_secret_from_db(token_id)

        assert return_secret.id == token_id

        assert return_secret.secret == secret.secret
        assert return_secret.encrypted_secret != secret.encrypted_secret
        assert type(return_secret.encrypted_secret) is bytes

        assert return_secret.comment == secret.comment
        assert return_secret.comment is not None

        assert return_secret.first_identified == secret.first_identified
        assert type(return_secret.first_identified) is datetime
        assert return_secret.first_identified is not None

        assert return_secret.live == secret.live
        assert return_secret.live is None

        assert return_secret.last_test_date == secret.last_test_date
        assert return_secret.last_test_date is None

        assert return_secret.last_test_success == secret.last_test_success
        assert return_secret.last_test_success is None

        assert return_secret.hashed_secret == secret.hashed_secret
        assert return_secret.hashed_secret is not None

        assert return_secret.other_factors == secret.other_factors
        assert return_secret.other_factors is not None

        assert return_secret.encrypted_other_factors != secret.encrypted_other_factors
        assert return_secret.encrypted_other_factors is not None

        assert return_secret.uuid == secret.uuid
        assert type(return_secret.uuid) is str
        assert return_secret.uuid is not None

        assert return_secret.owner_email == secret.owner_email
        assert return_secret.owner_email is not None

        assert return_secret.remediation_date == secret.remediation_date
        assert return_secret.remediation_date is None

        mock_vault.assert_called()

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    def test_query_update_change_value_query_integration(self, mock_vault, database_with_data, test_secret):
        db = DbBiz()
        db.conn = database_with_data

        # insert one entry into DB
        token_id = db.write_secret_to_db(test_secret)

        # query
        tz_now = datetime.now().astimezone(tz=timezone.utc)

        mock_vault.return_value.read_secret.return_value = {
            'secret': 'token_cred', 'other_factors': {'something': 'another thing'},
        }
        secret = db.get_secret_from_db(token_id)
        secret.is_live = True
        secret.last_test_date = tz_now
        secret.last_test_success = False
        secret.uuid = 'new-uuid'
        secret.token_hash = 'new-token_hash'
        secret.owner_email = 'new_owner@email.com'
        secret.remediation_date = tz_now
        secret.other_factors = {'factor': 'new_other_factor'}

        # update
        write_secret_id = db.write_secret_to_db(secret)
        assert write_secret_id is not None
        assert write_secret_id == token_id

        # query
        mock_vault.return_value.read_secret.return_value = {
            'secret': 'token_cred', 'other_factors': {'factor': 'new_other_factor'},
        }
        return_secret = db.get_secret_from_db(token_id)

        assert return_secret.id == token_id

        assert return_secret.secret == secret.secret
        assert return_secret.encrypted_secret != secret.encrypted_secret
        assert type(return_secret.encrypted_secret) is bytes

        assert return_secret.comment == secret.comment
        assert return_secret.comment is not None

        assert return_secret.first_identified == secret.first_identified
        assert type(return_secret.first_identified) is datetime
        assert return_secret.first_identified is not None

        assert return_secret.live == secret.live
        assert return_secret.live is None

        assert return_secret.last_test_date == secret.last_test_date
        assert return_secret.last_test_date.isoformat() == secret.last_test_date.isoformat()
        assert type(return_secret.last_test_date) is datetime
        assert return_secret.last_test_date is not None

        assert return_secret.last_test_success == secret.last_test_success
        assert return_secret.last_test_success is not None

        assert return_secret.hashed_secret == secret.hashed_secret
        assert return_secret.hashed_secret is not None

        assert return_secret.other_factors == secret.other_factors
        assert return_secret.other_factors != test_secret.other_factors
        assert return_secret.other_factors is not None

        assert return_secret.encrypted_other_factors != secret.encrypted_other_factors
        assert return_secret.encrypted_other_factors != test_secret.encrypted_other_factors
        assert return_secret.encrypted_other_factors is not None

        assert return_secret.uuid == secret.uuid
        assert type(return_secret.uuid) is str
        assert return_secret.uuid is not None

        assert return_secret.owner_email == secret.owner_email
        assert return_secret.owner_email is not None

        assert return_secret.remediation_date.isoformat() == secret.remediation_date.isoformat()
        assert return_secret.remediation_date == secret.remediation_date
        assert return_secret.remediation_date is not None
        assert type(return_secret.remediation_date) is datetime

        mock_vault.assert_called()
