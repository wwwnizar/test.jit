import jwt
import pytest
import responses
from detect_secrets.core.constants import VerifiedResult
from mock import MagicMock
from mock import patch

from detect_secrets_stream.validation.ibm_cloud_iam import IBMCloudIAMValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestIBMCloudIAMValidator:

    email_domain = 'test.test'

    @pytest.mark.parametrize(
        'result, expected_valid',
        [
            (VerifiedResult.VERIFIED_TRUE, True),
            (VerifiedResult.VERIFIED_FALSE, False),
        ],
    )
    @patch('detect_secrets.plugins.ibm_cloud_iam.IbmCloudIamDetector.verify')
    def test_validate_ibm_cloud_iam_key(self, mock_verify, result, expected_valid):
        mock_verify.return_value = result
        ibm_cloud_iam_validator = IBMCloudIAMValidator()
        valid = ibm_cloud_iam_validator.validate('test-token')
        assert valid is expected_valid

    @patch('detect_secrets.plugins.ibm_cloud_iam.IbmCloudIamDetector.verify')
    def test_validate_ibm_cloud_iam_key_unverifiable(self, mock_verify):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        ibm_cloud_iam_validator = IBMCloudIAMValidator()
        with pytest.raises(ValidationException):
            ibm_cloud_iam_validator.validate('test-token')

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_human_user(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {'email': f'email@{self.email_domain}'}
        validator = IBMCloudIAMValidator()
        owner = validator.resolve_owner('test-key')
        assert owner == f'email@{self.email_domain}'

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_service_id(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {'account': {'bss': 123}}
        jwt_token = jwt.encode({'test': 'dict'}, '').decode()
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            json={'access_token': jwt_token}, status=200,
        )
        responses.add(
            responses.GET, 'https://accounts.cloud.ibm.com/coe/v1/accounts/123/owner',
            json={'email': f'email@{self.email_domain}'}, status=200,
        )
        validator = IBMCloudIAMValidator()
        owner = validator.resolve_owner('test-key')
        assert owner == f'email@{self.email_domain}'

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_no_email_or_bss(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {'unrecognized': 'field'}
        validator = IBMCloudIAMValidator()
        owner = validator.resolve_owner('test-key')
        owner == ''

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_service_id_no_access_token(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {'account': {'bss': 123}}
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            json={'no': 'token'}, status=200,
        )
        validator = IBMCloudIAMValidator()
        with pytest.raises(ValidationException):
            validator.resolve_owner('test-key')

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_service_id_access_token_bad_request(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {'account': {'bss': 123}}
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            status=403,
        )
        responses.add(
            responses.GET, 'https://accounts.cloud.ibm.com/coe/v1/accounts/123/owner',
            json={'email': f'email@{self.email_domain}'}, status=200,
        )
        validator = IBMCloudIAMValidator()
        with pytest.raises(ValidationException):
            validator.resolve_owner('test-key')

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_service_id_no_email(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {'account': {'bss': 123}}
        jwt_token = jwt.encode({'test': 'dict'}, '').decode()
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            json={'access_token': jwt_token}, status=200,
        )
        responses.add(
            responses.GET, 'https://accounts.cloud.ibm.com/coe/v1/accounts/123/owner',
            json={'no': 'email'}, status=200,
        )
        validator = IBMCloudIAMValidator()
        with pytest.raises(ValidationException):
            validator.resolve_owner('test-key')

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_service_id_email_bad_request(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {'account': {'bss': 123}}
        jwt_token = jwt.encode({'test': 'dict'}, '').decode()
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            json={'access_token': jwt_token}, status=200,
        )
        responses.add(
            responses.GET, 'https://accounts.cloud.ibm.com/coe/v1/accounts/123/owner',
            status=403,
        )
        validator = IBMCloudIAMValidator()
        with pytest.raises(ValidationException):
            validator.resolve_owner('test-key')

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_resolve_owner_bad_request(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 404
        validator = IBMCloudIAMValidator()
        owner = validator.resolve_owner('test-key')
        assert owner == ''

    @responses.activate
    def test_generate_access_token(self):
        jwt_token = jwt.encode({'test': 'dict'}, '').decode()
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            json={'access_token': jwt_token}, status=200,
        )
        validator = IBMCloudIAMValidator()
        access_token = validator.generate_access_token('test-secret')
        assert access_token == jwt_token

    @responses.activate
    def test_generate_bad_request(self):
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            status=404,
        )
        validator = IBMCloudIAMValidator()
        with pytest.raises(Exception):
            validator.generate_access_token('test-secret')

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_uuid_and_name(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {
            'sub_type': 'ServiceId',
            'iam_id': 'iam-ServiceId-123test',
            'name': 'test-name',
        }
        validator = IBMCloudIAMValidator()
        service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name('test-key')
        assert service_id_uuid == 'iam-ServiceId-123test'
        assert service_id_name == 'test-name'

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_uuid_and_name_not_a_service_id(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {
            'sub_type': 'NOTServiceId',
            'iam_id': 'should-not-return',
            'name': 'these-fields',
        }
        validator = IBMCloudIAMValidator()
        service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name('test-key')
        assert service_id_uuid is None
        assert service_id_name is None

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_uuid_and_name_unexpected_field_names(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {
            'not_sub_type': 'oof',
            'not_iam_id': 'not-the-fields',
            'not_name': 'we-expected',
        }
        validator = IBMCloudIAMValidator()
        service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name('test-key')
        assert service_id_uuid is None
        assert service_id_name is None

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_uuid_and_name_some_unexpected_field_names_2(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {
            'sub_type': 'ServiceId',
            'not_iam_id': 'not-the-fields',
            'not_name': 'we-expected',
        }
        validator = IBMCloudIAMValidator()
        service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name('test-key')
        assert service_id_uuid is None
        assert service_id_name is None

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_uuid_and_name_only_uuid(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {
            'sub_type': 'ServiceId',
            'iam_id': 'iam-ServiceId-123test',
        }
        validator = IBMCloudIAMValidator()
        service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name('test-key')
        assert service_id_uuid == 'iam-ServiceId-123test'
        assert service_id_name is None

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_uuid_and_name_only_name(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.json.return_value = {
            'sub_type': 'ServiceId',
            'name': 'test-name',
        }
        validator = IBMCloudIAMValidator()
        service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name('test-key')
        assert service_id_uuid is None
        assert service_id_name == 'test-name'

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_bad_request(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200
        magic_mock_verify.status_code = 404
        validator = IBMCloudIAMValidator()
        service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name('test-key')
        assert service_id_uuid is None
        assert service_id_name is None

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_apikey_meta_good_meta(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200

        jwt_token = jwt.encode({'test': 'dict'}, '').decode()
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            json={'access_token': jwt_token}, status=200,
        )
        responses.add(
            responses.GET, 'https://iam.cloud.ibm.com/v1/apikeys/details',
            json={
                'id': 'ApiKey-11111111-1111-1111-1111-111111111111',
                'entity_tag': '<not sure the meaning of this field>',
                'crn': 'crn:v1:bluemix:public:iam-identity::a/xxxxxxx::apikey:xxxx',
                'locked': False,
                'created_at': '2019-01-03T10:07+0000',
                'modified_at': '2019-01-03T10:07+0000',
                'name': 'auto-generated-apikey-11111111-1111-1111-1111-1111111111111',
                'description': 'a good description of what this key is',
                'iam_id': '<iam_id>',
                'account_id': '<account_id>',
                'apikey': '<raw_apikey>',
            }, status=200,
        )
        validator = IBMCloudIAMValidator()
        meta = validator.get_service_id_apikey_meta('test-service_id_apikey')
        assert meta['id'] == 'ApiKey-11111111-1111-1111-1111-111111111111'
        assert meta['crn'] == 'crn:v1:bluemix:public:iam-identity::a/xxxxxxx::apikey:xxxx'
        assert meta['apikey'] == '<raw_apikey>'

    @responses.activate
    @patch('detect_secrets_stream.validation.ibm_cloud_iam.verify_cloud_iam_api_key')
    def test_get_service_id_apikey_meta_bad_meta_req(self, mock_verify):
        mock_verify.return_value = magic_mock_verify = MagicMock()
        magic_mock_verify.status_code = 200

        jwt_token = jwt.encode({'test': 'dict'}, '').decode()
        responses.add(
            responses.POST, 'https://iam.cloud.ibm.com/identity/token',
            json={'access_token': jwt_token}, status=200,
        )
        responses.add(
            responses.GET, 'https://iam.cloud.ibm.com/v1/apikeys/details',
            status=400,
        )
        validator = IBMCloudIAMValidator()
        meta = validator.get_service_id_apikey_meta('test-service_id_apikey')
        assert meta is None

    @pytest.mark.parametrize(
        'iam_conf_value',
        [
            ({}),
            ({'admin_apikey': None}),
            ({'admin_apikey': ''}),
        ],
    )
    @responses.activate
    @patch('detect_secrets_stream.util.conf.ConfUtil.load_iam_conf')
    def test_get_service_id_no_admin_key(self, mock_load_conf, iam_conf_value):
        mock_load_conf.return_value = iam_conf_value
        validator = IBMCloudIAMValidator()
        meta = validator.get_service_id_apikey_meta('test-service_id_apikey')
        assert meta is None
