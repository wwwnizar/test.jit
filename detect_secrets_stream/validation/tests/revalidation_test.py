import datetime
from unittest.mock import MagicMock

import pytest
from mock import patch

from detect_secrets_stream.scan_worker.commit import Commit
from detect_secrets_stream.scan_worker.secret import Secret
from detect_secrets_stream.validation.revalidation import Revalidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestRevalidator:

    @pytest.fixture
    def test_secret(self):
        secret = Secret('test_secret', 'secret_type')
        secret.lookup_token_owner = MagicMock()
        secret.verify = MagicMock()
        return secret

    @pytest.fixture
    def test_commit(self):
        commit = Commit('test_hash', 'test_repo', 'test_branch')
        return commit

    @pytest.fixture
    def test_revalidator(self):
        revalidator = Revalidator()

        revalidator.get_db = mock_get_db = MagicMock()
        mock_get_db.return_value = mock_db_inst = MagicMock()

        return (revalidator, mock_db_inst)

    def test_fix_owner(self, test_secret, test_revalidator):
        test_secret.owner_email = None
        revalidator, mock_db_inst = test_revalidator

        mock_db_inst.get_secret_from_db.return_value = test_secret
        mock_db_inst.write_secret_to_db.return_value = True

        fix_result = revalidator.fix_owner(test_secret.id)

        assert fix_result is True
        test_secret.lookup_token_owner.assert_called()
        mock_db_inst.get_secret_from_db.assert_called()
        mock_db_inst.write_secret_to_db.assert_called_with(test_secret)

    def test_fix_owner_replace(self, test_secret, test_revalidator):
        test_secret.owner_email = 'would_be_replaced@email.com'
        revalidator, mock_db_inst = test_revalidator

        mock_db_inst.get_secret_from_db.return_value = test_secret
        mock_db_inst.write_secret_to_db.return_value = True

        fix_result = revalidator.fix_owner(test_secret.id, replace=True)

        assert fix_result is True
        test_secret.lookup_token_owner.assert_called()
        mock_db_inst.get_secret_from_db.assert_called()
        mock_db_inst.write_secret_to_db.assert_called_with(test_secret)

    def test_fix_owner_no_id(self, test_secret, test_revalidator):
        test_secret.owner_email = None
        revalidator, mock_db_inst = test_revalidator

        mock_db_inst.get_secret_from_db.return_value = None
        mock_db_inst.write_secret_to_db.return_value = True

        fix_result = revalidator.fix_owner(test_secret.id)

        assert fix_result is False
        test_secret.lookup_token_owner.assert_not_called()
        mock_db_inst.get_secret_from_db.assert_called()
        mock_db_inst.write_secret_to_db.assert_not_called()

    def test_revalidate_true(self, test_secret, test_revalidator):
        revalidator, mock_db_inst = test_revalidator

        test_secret.verify.return_value = True
        assert test_secret.live is not True
        assert test_secret.last_test_success is not True

        mock_db_inst.get_secret_from_db.return_value = test_secret
        mock_db_inst.write_secret_to_db.return_value = True

        fix_result = revalidator.revalidate(test_secret.id)

        assert fix_result is True
        test_secret.verify.assert_called()
        assert test_secret.live is True
        assert test_secret.last_test_success is True
        assert type(test_secret.last_test_date) is datetime.datetime
        assert test_secret.remediation_date is None
        mock_db_inst.get_secret_from_db.assert_called()
        mock_db_inst.write_secret_to_db.assert_called_with(test_secret)

    def test_revalidate_false(self, test_secret, test_revalidator):
        revalidator, mock_db_inst = test_revalidator
        test_secret.verify.return_value = False
        assert test_secret.live is not True
        assert test_secret.last_test_success is not True

        mock_db_inst.get_secret_from_db.return_value = test_secret
        mock_db_inst.write_secret_to_db.return_value = True

        fix_result = revalidator.revalidate(test_secret.id)

        assert fix_result is True
        test_secret.verify.assert_called()
        assert test_secret.live is False
        assert test_secret.last_test_success is False
        assert type(test_secret.last_test_date) is datetime.datetime
        assert type(test_secret.remediation_date) is datetime.datetime
        mock_db_inst.get_secret_from_db.assert_called()
        mock_db_inst.write_secret_to_db.assert_called_with(test_secret)

    def test_revalidate_exception(self, test_secret, test_revalidator):
        revalidator, mock_db_inst = test_revalidator
        test_secret.verify.side_effect = ValidationException('Fail to validate')
        old_live = test_secret.live
        assert test_secret.live is not True
        assert test_secret.last_test_success is not True

        mock_db_inst.get_secret_from_db.return_value = test_secret
        mock_db_inst.write_secret_to_db.return_value = True

        fix_result = revalidator.revalidate(test_secret.id)

        assert fix_result is True
        test_secret.verify.assert_called()
        assert test_secret.live is old_live
        assert test_secret.last_test_success is None
        assert type(test_secret.last_test_date) is datetime.datetime
        assert test_secret.remediation_date is None
        mock_db_inst.get_secret_from_db.assert_called()
        mock_db_inst.write_secret_to_db.assert_called_with(test_secret)

    def test_revalidate_no_token(self, test_secret, test_revalidator):
        revalidator, mock_db_inst = test_revalidator
        mock_db_inst.get_secret_from_db.return_value = None
        mock_db_inst.write_secret_to_db.return_value = True

        fix_result = revalidator.revalidate(test_secret.id)

        assert fix_result is False
        test_secret.verify.assert_not_called()
        mock_db_inst.get_secret_from_db.assert_called()
        mock_db_inst.write_secret_to_db.assert_not_called()

    @patch('detect_secrets_stream.secret_corpus_db.db_biz.Vault')
    def test_get_db(self, mock_vault):
        revalidator = Revalidator()
        assert revalidator.db is None

        revalidator.get_db()
        assert revalidator.db is not None

        db = revalidator.db
        revalidator.get_db()
        assert revalidator.db == db

    def test_revalidate_all(self, test_revalidator):
        revalidator, mock_db_inst = test_revalidator
        token_ids = [1, 2]
        mock_db_inst.get_live_tokens.return_value = token_ids
        revalidator.revalidate = MagicMock()
        revalidator.revalidate.side_effect = [True, Exception('Fail to validate')]

        revalidator.revalidate_all()

        revalidator.revalidate.assert_called()
        for token_id in token_ids:
            revalidator.revalidate.assert_any_call(token_id)
        assert revalidator.revalidate.call_count == len(token_ids)
