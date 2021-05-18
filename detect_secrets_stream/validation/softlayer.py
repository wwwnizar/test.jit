import logging

import requests
from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.softlayer import SoftlayerDetector
from detect_secrets.plugins.softlayer import verify_softlayer_key

from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class SoftlayerValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return SoftlayerDetector.secret_type

    def get_username(self, other_factors):
        return self.get_key_from_other_factors('username', other_factors)

    def validate(self, secret, other_factors) -> bool:
        username = self.get_username(other_factors)
        token = secret
        result = verify_softlayer_key(username, token)

        if result == VerifiedResult.VERIFIED_TRUE:
            return True
        elif result == VerifiedResult.VERIFIED_FALSE:
            return False
        else:
            raise ValidationException(
                'Fail to validate Softlayer token',
            )

    def resolve_owner(self, secret, other_factors):
        '''
        Owner resolution follows priority like below

        1. username if username is an email
        2. SoftLayer_Account.json - response['email']
        3. empty string
        '''
        username = self.get_username(other_factors)
        token = secret

        if '@' in username:
            return username

        email = ''
        response = requests.get(
            'https://api.softlayer.com/rest/v3/SoftLayer_Account.json',
            auth=(username, token),
            headers={
                'Content-type': 'application/json',
            },
        ).json()
        self.logger.info(f'SoftLayer_Account.json response: {response}')

        if 'email' in response and response['email']:
            email = response['email']

        return email

    def revoke(self, secret, other_factors, secret_id):
        pass
