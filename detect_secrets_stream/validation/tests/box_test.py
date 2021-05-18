import pytest
from mock import patch

from detect_secrets_stream.validation.box import BoxValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestBoxValidator:

    @pytest.mark.parametrize(
        'result, expected_valid',
        [
            ('user', True),
            (None, False),
        ],
    )
    @patch('detect_secrets_stream.validation.box.get_box_user')
    def test_validate_box_credentials(self, mock_verify, result, expected_valid):
        mock_verify.return_value = result
        other_factors = {
            'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
            'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
            'enterpriseID': 'test-enterprise-id',
        }

        box_validator = BoxValidator()
        valid = box_validator.validate('test-token', other_factors)
        assert valid is expected_valid

    @pytest.mark.parametrize(
        'other_factors',
        [
            {
                'publicKeyID': 'test-public-key-id',
                'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id',
                'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
                'passphrase': 'test-passphrase',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
                'privateKey': 'test-private-key',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
                'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
            },
        ],
    )
    def test_validate_with_missing_factors(self, other_factors):
        validator = BoxValidator()
        with pytest.raises(ValidationException, match=r'Missing'):
            assert validator.validate('password', other_factors)

    @patch('detect_secrets_stream.validation.box.get_box_user')
    def test_resolve_owner(self, mock_verify):
        mock_verify.return_value = 'Testy McTestingson'
        validator = BoxValidator()

        other_factors = {
            'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
            'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
            'enterpriseID': 'test-enterprise-id',
        }
        owner = validator.resolve_owner('test-secret', other_factors)
        assert owner == 'Testy McTestingson'

    @patch('detect_secrets_stream.validation.box.get_box_user')
    def test_resolve_owner_fails(self, mock_verify):
        mock_verify.return_value = None
        validator = BoxValidator()

        other_factors = {
            'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
            'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
            'enterpriseID': 'test-enterprise-id',
        }
        assert validator.resolve_owner('password', other_factors) == ''

    @pytest.mark.parametrize(
        'other_factors',
        [
            {
                'publicKeyID': 'test-public-key-id',
                'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id',
                'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
                'passphrase': 'test-passphrase',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
                'privateKey': 'test-private-key',
                'enterpriseID': 'test-enterprise-id',
            },
            {
                'clientID': 'test-client-id', 'publicKeyID': 'test-public-key-id',
                'privateKey': 'test-private-key', 'passphrase': 'test-passphrase',
            },
        ],
    )
    def test_resolve_owner_with_missing_factors(self, other_factors):
        validator = BoxValidator()
        with pytest.raises(ValidationException, match=r'Missing'):
            assert validator.resolve_owner('password', other_factors)
