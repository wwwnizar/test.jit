import pytest
from detect_secrets.core.constants import VerifiedResult
from mock import patch

from detect_secrets_stream.validation.db2 import DB2Validator
from detect_secrets_stream.validation.validateException import ValidationException


class TestDB2Validator:

    @pytest.mark.parametrize(
        'result, expected_valid',
        [
            (VerifiedResult.VERIFIED_TRUE, True),
            (VerifiedResult.VERIFIED_FALSE, False),
        ],
    )
    @patch('detect_secrets_stream.validation.db2.verify_db2_credentials')
    def test_validate_db2_token(self, mock_verify, result, expected_valid):
        mock_verify.return_value = result
        other_factors = {'username': 'test-user', 'database': 'test-db', 'port': '1', 'hostname': 'host.test'}

        db2_validator = DB2Validator()
        valid = db2_validator.validate('test-token', other_factors)
        assert valid is expected_valid

    @patch('detect_secrets_stream.validation.db2.verify_db2_credentials')
    def test_validate_db2_token_unverifiable(self, mock_verify):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        other_factors = {'username': 'test-user', 'database': 'test-db', 'port': '1', 'hostname': 'host.test'}

        db2_validator = DB2Validator()
        with pytest.raises(ValidationException):
            db2_validator.validate('test-token', other_factors)

    @pytest.mark.parametrize(
        'other_factors',
        [
            {'username': 'test-user', 'database': 'test-db', 'port': '1'},
            {'username': 'test-user', 'database': 'test-db', 'hostname': 'host.test'},
            {'port': '1', 'database': 'test-db', 'hostname': 'host.test'},
            {'port': '1', 'username': 'test-user', 'hostname': 'host.test'},
        ],
    )
    def test_validate_with_missing_factors(self, other_factors):
        validator = DB2Validator()
        with pytest.raises(ValidationException, match=r'Missing'):
            assert validator.validate('password', other_factors)

    def test_resolve_owner(self):
        validator = DB2Validator()
        username = 'some-db2-user'
        owner = validator.resolve_owner('password', {'username': username})
        assert owner == username

    @pytest.mark.parametrize('other_factors', [None, {'not-username': 'oops'}])
    def test_resolve_missing_username(self, other_factors):
        validator = DB2Validator()
        with pytest.raises(ValidationException):
            assert validator.resolve_owner('password', other_factors) is None
