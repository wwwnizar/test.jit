import logging

import requests
from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.ibm_cloud_iam import IbmCloudIamDetector
from detect_secrets.plugins.ibm_cloud_iam import verify_cloud_iam_api_key

from ..util.conf import ConfUtil
from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class IBMCloudIAMValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return IbmCloudIamDetector.secret_type

    def validate(self, secret, other_factors=None):
        try:
            result = IbmCloudIamDetector().verify(secret)
            if result == VerifiedResult.VERIFIED_TRUE:
                return True
            elif result == VerifiedResult.VERIFIED_FALSE:
                return False
            else:
                raise ValidationException(
                    'Failed to validate IBM Cloud IAM token. '
                    f'{result} is neither VERIFIED_TRUE or VERIFIED_FALSE.',
                )
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException(
                'Failed to validate IBM Cloud IAM token.',
            )

    def generate_access_token(self, secret):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        response = requests.post(
            'https://iam.cloud.ibm.com/identity/token',
            headers=headers,
            data={
                'grant_type': 'urn:ibm:params:oauth:grant-type:apikey',
                'apikey': secret,
            },
        )
        return response.json()['access_token']

    def resolve_owner(self, secret, other_factors=None):
        """
        Returns: user email if key belongs to a user or service
                 account owner email if key belongs to a service id
                 empty string if email resolution not possible
        """
        response = verify_cloud_iam_api_key(secret)
        if response.status_code != 200:
            return ''

        try:
            response_json = response.json()
            if 'email' in response_json:
                return response_json['email']
            elif 'account' in response_json and 'bss' in response_json['account']:
                account_id = response_json['account']['bss']
                if type(secret) == bytes:
                    secret = secret.decode('UTF-8')
                access_token = self.generate_access_token(secret)
                headers = {'Authorization': 'Bearer %s' % access_token}
                url = f'https://accounts.cloud.ibm.com/coe/v1/accounts/{account_id}/owner'
                response = requests.get(url, headers=headers)
                return response.json()['email']
            else:
                return ''
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException('Failed to resolve IBM Cloud IAM token owner.')

    def get_service_id_uuid_and_name(self, secret):
        """
        Returns: tuple of service id uuid and service id name if key belongs to a service id
        """
        response = verify_cloud_iam_api_key(secret)
        if response.status_code != 200:
            return (None, None)

        try:
            uuid = None
            name = None
            response_json = response.json()
            if 'sub_type' in response_json \
                    and response_json['sub_type'] == 'ServiceId':
                if 'iam_id' in response_json:
                    uuid = response_json['iam_id']
                if 'name' in response_json:
                    name = response_json['name']
            return (uuid, name)
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException('Failed to resolve IBM Cloud IAM service ID.')

    def get_service_id_apikey_meta(self, service_id_apikey):
        """
        Returns: metadata for an iam-apikey
        """
        gd_iam_conf = ConfUtil.load_iam_conf()
        if 'admin_apikey' not in gd_iam_conf or not gd_iam_conf['admin_apikey']:
            return None
        else:
            admin_iam_apikey = gd_iam_conf['admin_apikey']

            admin_iam_token = self.generate_access_token(admin_iam_apikey)
            headers = {
                'Authorization': 'Bearer ' + admin_iam_token,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'IAM-ApiKey': service_id_apikey,
            }

            response = requests.get(
                'https://iam.cloud.ibm.com/v1/apikeys/details',
                headers=headers,
            )
            if response.status_code != 200:
                return (None)

            meta = response.json()

            return meta

    def revoke(self, secret, other_factors, secret_id):
        pass
