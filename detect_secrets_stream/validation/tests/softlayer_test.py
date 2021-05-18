from unittest.mock import patch

import pytest
import responses
from detect_secrets.core.constants import VerifiedResult

from detect_secrets_stream.validation.softlayer import SoftlayerValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestSoftlayer:

    @patch('detect_secrets_stream.validation.softlayer.verify_softlayer_key')
    def test_validate_valid(self, mock_verify):
        mock_verify.return_value = VerifiedResult.VERIFIED_TRUE
        validator = SoftlayerValidator()
        assert validator.validate('password', {'username': 'name'}) is True

    @patch('detect_secrets_stream.validation.softlayer.verify_softlayer_key')
    def test_validate_invalid(self, mock_verify):
        mock_verify.return_value = VerifiedResult.VERIFIED_FALSE
        validator = SoftlayerValidator()
        assert validator.validate('password', {'username': 'name'}) is False

    @patch('detect_secrets_stream.validation.softlayer.verify_softlayer_key')
    def test_validate_error(self, mock_verify):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        validator = SoftlayerValidator()
        with pytest.raises(ValidationException, match=r'Fail to validate'):
            validator.validate('password', {'username': 'name'})

    @pytest.mark.parametrize(
        'other_factors',
        [
            None,
            {},
            'not a dict',
            {'missing': 'username'},
        ],
    )
    @patch('detect_secrets_stream.validation.softlayer.verify_softlayer_key')
    def test_validate_wrong_input(self, mock_verify, other_factors):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        validator = SoftlayerValidator()
        with pytest.raises(ValidationException):
            validator.validate('password', other_factors)

    def test_resolve_owner_username_email(self):
        validator = SoftlayerValidator()
        username = 'some@one.email'
        owner = validator.resolve_owner('password', {'username': username})
        assert owner == username

    @responses.activate
    def test_resolve_owner_response_email(self):
        email = 'my@email.com'
        responses.add(
            responses.GET, 'https://api.softlayer.com/rest/v3/SoftLayer_Account.json',
            json={'email': email}, status=200,
        )
        validator = SoftlayerValidator()
        owner = validator.resolve_owner('password', {'username': 'name'})
        assert owner == email

    @responses.activate
    def test_resolve_owner_response_no_email(self):
        responses.add(
            responses.GET, 'https://api.softlayer.com/rest/v3/SoftLayer_Account.json',
            json={}, status=200,
        )
        validator = SoftlayerValidator()
        owner = validator.resolve_owner('password', {'username': 'name'})
        assert owner == ''

    @pytest.mark.parametrize('other_factors', [None, {}])
    def test_resolve_owner_wrong_input(self, other_factors):
        validator = SoftlayerValidator()
        with pytest.raises(ValidationException):
            assert validator.resolve_owner('password', other_factors) is None
