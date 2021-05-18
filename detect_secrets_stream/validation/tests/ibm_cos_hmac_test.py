import pytest
from mock import MagicMock
from mock import patch

from detect_secrets_stream.validation.ibm_cos_hmac import IBMCosHmacValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestIBMCosHmacValidator:

    @patch('detect_secrets_stream.validation.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_validate_ibm_cos_token_valid(self, mock_verify):
        mock_verify.return_value = True
        validator = IBMCosHmacValidator()
        valid = validator.validate('test-token', other_factors={'access_key_id': 'test-key'})
        assert valid is True

    @patch('detect_secrets_stream.validation.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_validate_ibm_cos_token_invalid(self, mock_verify):
        mock_verify.return_value = False
        validator = IBMCosHmacValidator()
        valid = validator.validate('test-token', other_factors={'access_key_id': 'test-key'})
        assert valid is False

    @patch('detect_secrets_stream.validation.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_validate_ibm_cos_token_no_second_factor(self, mock_verify):
        validator = IBMCosHmacValidator()
        with pytest.raises(ValidationException):
            validator.validate('test-token', None)

    @patch('detect_secrets_stream.validation.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_validate_ibm_cos_token_wrong_second_factor(self, mock_verify):
        validator = IBMCosHmacValidator()
        with pytest.raises(ValidationException):
            validator.validate('test-token', other_factors={'wrong': '2nd-factor'})

    @patch('detect_secrets_stream.validation.ibm_cos_hmac.verify_ibm_cos_hmac_credentials')
    def test_validate_ibm_cos_token_exp(self, mock_verify):
        mock_verify.side_effect = Exception('bummer')
        validator = IBMCosHmacValidator()
        with pytest.raises(ValidationException):
            validator.validate('test-token', other_factors={'access_key_id': 'test-key'})

    @pytest.mark.parametrize(
        ('service_id', 'text'),
        [
            ('44444444-3333-4444-2222-777777777777', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>44444444-3333-4444-2222-777777777777</ID><DisplayName>44444444-3333-4444-2222-777777777777</DisplayName></Owner><Buckets><Bucket><Name>test</Name><CreationDate>2019-09-30T18:33:23.328Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>'),  # noqa: E501
            ('', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>test</Name><CreationDate>2019-09-30T18:33:23.328Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>'),  # noqa: E501
        ],
    )
    @patch('detect_secrets_stream.validation.ibm_cos_hmac.query_ibm_cos_hmac')
    def test_resolve_ibm_cos_owner_email(self, mock_query, service_id, text):
        email_mock = MagicMock(status_code=200)
        email_mock.text = text
        mock_query.side_effect = [
            email_mock,
        ]

        validator = IBMCosHmacValidator()
        owner = validator.resolve_owner(
            'test-access-key',
            {'access_key_id': 'test-secret-access-key'},
        )
        assert owner == service_id

    @patch('detect_secrets_stream.validation.ibm_cos_hmac.query_ibm_cos_hmac')
    def test_resolve_ibm_cos_owner_bad_credential(self, mock_query):
        email_mock = MagicMock(status_code=403)
        mock_query.side_effect = [
            email_mock,
        ]

        validator = IBMCosHmacValidator()
        owner = validator.resolve_owner(
            'test-access-key',
            {'access_key_id': 'test-secret-access-key'},
        )
        assert owner == ''

    @patch('detect_secrets_stream.validation.ibm_cos_hmac.query_ibm_cos_hmac')
    def test_resolve_ibm_cos_owner_exp(self, mock_query):
        mock_query.side_effect = Exception('bummer')

        validator = IBMCosHmacValidator()
        with pytest.raises(Exception):
            validator.resolve_owner(
                'test-access-key',
                {'access_key_id': 'test-secret-access-key'},
            )
