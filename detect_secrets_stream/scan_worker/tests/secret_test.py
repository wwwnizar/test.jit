import json
from unittest import mock
from unittest import TestCase
from unittest.mock import patch

import pytest

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.scan_worker.secret import Secret
from detect_secrets_stream.secret_corpus_db.vault_read_exception import VaultReadException
from detect_secrets_stream.security.security import Decryptor
from detect_secrets_stream.security.security import DeterministicCryptor
from detect_secrets_stream.validation.validateException import ValidationException


class SecretTest (TestCase):

    def setUp(self):
        self.secret = Secret('test_secret', 'test_type')
        self.decryptor = Decryptor()
        self.determ_decryptor = DeterministicCryptor()
        self.email_domain = 'test.test'

    def test_gen_uuid(self):
        test_uuid = self.secret.uuid
        assert test_uuid is not None
        assert type(test_uuid) is str

    def test_hash_secret(self):
        self.assertNotEqual(self.secret.hashed_secret, None)
        self.assertNotEqual(self.secret.hashed_secret, self.secret.secret)

    def test_encrypt_other_factors(self):
        second_factor = {'second factor': 'another_one'}
        self.secret.other_factors = second_factor

        decrypted_other_factors = self.decryptor.decrypt(self.secret.encrypted_other_factors)
        self.assertEqual(decrypted_other_factors, json.dumps(second_factor))

    @patch('detect_secrets_stream.scan_worker.secret.ValidatorFactory.get_validator')
    def test_lookup_token_owner(self, mock_get_validator):
        mock_get_validator.return_value = mock_validator_inst = mock.MagicMock()
        mock_validator_inst.resolve_owner.return_value = None

        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'Slack Token')
        owner = secret.lookup_token_owner()

        assert owner == ''
        mock_validator_inst.resolve_owner.assert_called()
        mock_validator_inst.resolve_owner.assert_called_with(raw_secret, None)

    @patch('detect_secrets_stream.scan_worker.secret.ValidatorFactory.get_validator')
    def test_lookup_token_owner_internal_email(self, mock_get_validator):
        mock_get_validator.return_value = mock_validator_inst = mock.MagicMock()
        mock_validator_inst.resolve_owner.return_value = f'someone@us.{self.email_domain}'

        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'Slack Token')
        owner = secret.lookup_token_owner()

        assert owner == f'someone@us.{self.email_domain}'
        mock_validator_inst.resolve_owner.assert_called()
        mock_validator_inst.resolve_owner.assert_called_with(raw_secret, None)

    @patch('detect_secrets_stream.scan_worker.secret.ValidatorFactory.get_validator')
    def test_lookup_token_owner_external_email(self, mock_get_validator):
        mock_get_validator.return_value = mock_validator_inst = mock.MagicMock()
        mock_validator_inst.resolve_owner.return_value = 'someone@gmail.com'

        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'Slack Token')
        owner = secret.lookup_token_owner()

        assert owner == ''
        mock_validator_inst.resolve_owner.assert_called()
        mock_validator_inst.resolve_owner.assert_called_with(raw_secret, None)

    @patch('detect_secrets_stream.scan_worker.secret.ValidatorFactory.get_validator')
    def test_lookup_token_owner_external_filter_false(self, mock_get_validator):
        mock_get_validator.return_value = mock_validator_inst = mock.MagicMock()
        mock_validator_inst.resolve_owner.return_value = 'someone@gmail.com'

        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'Slack Token')
        owner = secret.lookup_token_owner(filter_out_external=False)

        assert owner == 'someone@gmail.com'
        mock_validator_inst.resolve_owner.assert_called()
        mock_validator_inst.resolve_owner.assert_called_with(raw_secret, None)

    def test_lookup_token_owner_invalid_type(self):
        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'test_type')
        assert secret.lookup_token_owner() is None
        assert secret.owner_email is None

    def test_verify_unknown_type(self):
        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'test_type')
        with pytest.raises(ValidationException, match=r'test_type'):
            secret.verify()

    @patch('detect_secrets_stream.scan_worker.secret.ValidatorFactory.get_validator')
    def test_verify_token(self, mock_get_validator):
        mock_get_validator.return_value = mock_validator_inst = mock.MagicMock()

        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'Slack Token')

        secret.verify()

        mock_validator_inst.validate.assert_called()
        mock_validator_inst.validate.assert_called_with(raw_secret, None)

    def test_revoke_unknown_type(self):
        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'test_type')
        with pytest.raises(RevocationException, match=r'test_type'):
            secret.revoke()

    @patch('detect_secrets_stream.scan_worker.secret.ValidatorFactory.get_validator')
    def test_revoke_token(self, mock_get_validator):
        mock_get_validator.return_value = mock_validator_inst = mock.MagicMock()

        raw_secret = 'test_secret'
        secret = Secret(raw_secret, 'Slack Token')

        secret.revoke()

        mock_validator_inst.revoke.assert_called()
        mock_validator_inst.revoke.assert_called_with(
            secret.secret, secret.other_factors, secret.id,
        )

    def test_setters(self):
        raw_secret = 'test_secret'
        raw_other_factors = {'first': 'one'}
        secret = Secret(raw_secret, 'test_type')
        secret.other_factors = raw_other_factors

        raw_encrypted_secret = secret.encrypted_secret
        raw_encrypted_other_factors = secret.encrypted_other_factors
        raw_hashed_secret = secret.hashed_secret

        secret.secret = raw_secret + ' new value'
        assert secret.encrypted_secret != raw_encrypted_secret
        assert secret.hashed_secret != raw_hashed_secret
        assert secret.secret == 'test_secret new value'

        new_other_factors = raw_other_factors.copy()
        new_other_factors.update({'another': 'one'})
        secret.other_factors = new_other_factors
        assert secret.encrypted_other_factors != raw_encrypted_other_factors
        assert secret.hashed_secret != raw_hashed_secret
        assert secret.other_factors == {'another': 'one', 'first': 'one'}

    @patch('detect_secrets_stream.scan_worker.secret.Vault')
    def test_read_secret_from_vault(self, mock_vault):
        mock_vault.return_value.read_secret.return_value = {
            'secret': 'LEAKED!', 'other_factors': {'email': 'also leaked'},
        }

        self.secret.id = 1
        self.secret.read_secret_from_vault()

        assert self.secret.secret == 'LEAKED!'
        assert self.secret.other_factors == {'email': 'also leaked'}

    @patch('detect_secrets_stream.scan_worker.secret.Vault')
    def test_read_secret_from_vault_no_other_factors(self, mock_vault):
        mock_vault.return_value.read_secret.return_value = {'secret': 'LEAKED!', 'other_factors': None}

        self.secret.id = 1
        self.secret.read_secret_from_vault()

        assert self.secret.secret == 'LEAKED!'
        assert self.secret.other_factors is None

    @patch('detect_secrets_stream.scan_worker.secret.Vault')
    def test_read_secret_from_vault_does_not_exist(self, mock_vault):
        mock_vault.return_value.read_secret.side_effect = Exception('secret not in vault or id not set')

        with pytest.raises(VaultReadException):
            self.secret.read_secret_from_vault()

    def test_is_ready_for_vault_insert(self):
        self.secret.id = 1
        self.secret.encrypted_secret = 'test-secret'
        assert self.secret.is_ready_for_vault_insert()

        self.secret.id = 1
        self.secret.secret = 'test-secret'
        assert self.secret.is_ready_for_vault_insert()

    def test_is_not_ready_for_vault_insert(self):
        self.secret.id = 1
        self.secret.secret = None
        assert not self.secret.is_ready_for_vault_insert()

        self.secret.id = None
        self.secret.secret = 'test-secret'
        assert not self.secret.is_ready_for_vault_insert()

        self.secret.id = None
        self.secret.encrypted_secret = 'test-secret-enc'
        self.secret.other_factors = None
        assert not self.secret.is_ready_for_vault_insert()

        self.secret.id = None
        self.secret.encrypted_secret = 'test-secret-enc'
        self.secret.other_factors = {'another': 'one'}
        self.secret.encrypted_other_factors = 'test-other-factors-enc'
        assert not self.secret.is_ready_for_vault_insert()

    def test_is_ready_for_revalidated_db_update(self):
        assert not self.secret.is_ready_for_revalidated_db_update()

        self.secret.id = 1
        assert not self.secret.is_ready_for_revalidated_db_update()

        assert self.secret.secret_type is not None
        assert not self.secret.is_ready_for_revalidated_db_update()

        self.secret.uuid = 'test-uuid'
        assert not self.secret.is_ready_for_revalidated_db_update()

        self.secret.hashed_secret = 'test-hashed-secret'
        assert not self.secret.is_ready_for_revalidated_db_update()

        self.secret.last_test_date = 'test-last-test-date'
        assert not self.secret.is_ready_for_revalidated_db_update()

        self.secret.live = True
        assert not self.secret.is_ready_for_revalidated_db_update()

        self.secret.first_identified = 'test-first-identified'
        assert self.secret.is_ready_for_revalidated_db_update()

    def test_delete_pi(self):
        self.secret.owner_email = 'test-email'
        self.secret.secret = 'test-secret'
        self.secret.hashed_secret = 'test-hashed-secret'
        self.secret.encrypted_secret = 'test-encrypted-other-factors'
        self.secret.other_factors = {'another': 'one'}

        self.secret.delete_pi()

        assert self.secret.owner_email == ''
        assert self.secret.secret == ''
        assert self.secret.hashed_secret == ''
        assert self.secret.encrypted_secret == ''
        assert self.secret.other_factors == ''

        assert self.secret.is_pi_cleaned()

    def test_is_pi_cleaned(self):
        self.secret.owner_email = 'test-email'
        self.secret.secret = 'test-secret'
        self.secret.hashed_secret = 'test-hashed-secret'
        self.secret.encrypted_secret = 'test-encrypted-other-factors'
        self.secret.other_factors = {'another': 'one'}

        assert not self.secret.is_pi_cleaned()
        self.secret.owner_email = ''
        assert not self.secret.is_pi_cleaned()
        self.secret.secret = ''
        assert not self.secret.is_pi_cleaned()
        self.secret.other_factors = ''
        assert not self.secret.is_pi_cleaned()
        self.secret.encrypted_secret = ''
        assert not self.secret.is_pi_cleaned()
        self.secret.hashed_secret = ''
        assert self.secret.is_pi_cleaned()

        # None also works
        self.secret.owner_email = None
        self.secret.secret = None
        self.secret.encrypted_secret = None
        self.secret.other_factors = None
        self.secret.hashed_secret = None

        assert self.secret.is_pi_cleaned()
