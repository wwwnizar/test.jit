from unittest.mock import patch

import pytest
from detect_secrets.core.constants import VerifiedResult

from detect_secrets_stream.validation.cloudant import CloudantValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestCloudant:

    @patch('detect_secrets_stream.validation.cloudant.verify_cloudant_key')
    def test_validate_valid(self, mock_verify):
        mock_verify.return_value = VerifiedResult.VERIFIED_TRUE
        validator = CloudantValidator()
        assert validator.validate('password', {'hostname': 'name'}) is True

    @patch('detect_secrets_stream.validation.cloudant.verify_cloudant_key')
    def test_validate_invalid(self, mock_verify):
        mock_verify.return_value = VerifiedResult.VERIFIED_FALSE
        validator = CloudantValidator()
        assert validator.validate('password', {'hostname': 'name'}) is False

    @patch('detect_secrets_stream.validation.cloudant.verify_cloudant_key')
    def test_validate_error(self, mock_verify):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        validator = CloudantValidator()
        with pytest.raises(ValidationException, match=r'Fail to validate'):
            validator.validate('password', {'hostname': 'name'})

    @pytest.mark.parametrize(
        'other_factors',
        [
            None,
            {},
            'not a dict',
            {'missing': 'hostname'},
        ],
    )
    @patch('detect_secrets_stream.validation.cloudant.verify_cloudant_key')
    def test_validate_wrong_input(self, mock_verify, other_factors):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        validator = CloudantValidator()
        with pytest.raises(ValidationException):
            validator.validate('password', other_factors)

    def test_resolve_owner_username_email(self):
        validator = CloudantValidator()
        username = ''
        owner = validator.resolve_owner('password', {'hostname': username})
        assert owner == username
