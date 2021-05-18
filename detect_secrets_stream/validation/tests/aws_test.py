import pytest
from mock import patch

from detect_secrets_stream.validation.aws import AWSValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestAWSValidator:

    @patch('detect_secrets_stream.validation.aws.verify_aws_secret_access_key')
    def test_validate_aws_token_valid(self, mock_verify):
        mock_verify.return_value = True
        aws_validator = AWSValidator()
        valid = aws_validator.validate('test-token', other_factors={'secret_access_key': 'test-key'})
        assert valid is True

    @patch('detect_secrets_stream.validation.aws.verify_aws_secret_access_key')
    def test_validate_aws_token_invalid(self, mock_verify):
        mock_verify.return_value = False
        aws_validator = AWSValidator()
        valid = aws_validator.validate('test-token', other_factors={'secret_access_key': 'test-key'})
        assert valid is False

    @patch('detect_secrets_stream.validation.aws.verify_aws_secret_access_key')
    def test_validate_aws_token_no_second_factor(self, mock_verify):
        aws_validator = AWSValidator()
        with pytest.raises(ValidationException):
            aws_validator.validate('test-token')

    @patch('detect_secrets_stream.validation.aws.verify_aws_secret_access_key')
    def test_validate_aws_token_wrong_second_factor(self, mock_verify):
        aws_validator = AWSValidator()
        with pytest.raises(ValidationException):
            aws_validator.validate('test-token', other_factors={'wrong': '2nd-factor'})

    def test_resolve_owner(self):
        aws_validator = AWSValidator()
        username = ''
        owner = aws_validator.resolve_owner(
            'test-access-key',
            {'secret_access_key': 'test-secret_access_key'},
        )
        assert owner == username
