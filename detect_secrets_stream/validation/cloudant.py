import logging

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.cloudant import CloudantDetector
from detect_secrets.plugins.cloudant import verify_cloudant_key

from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class CloudantValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return CloudantDetector.secret_type

    def validate(self, secret, other_factors) -> bool:
        username = self.get_key_from_other_factors('hostname', other_factors)

        token = secret
        result = verify_cloudant_key(username, token)

        if result == VerifiedResult.VERIFIED_TRUE:
            return True
        elif result == VerifiedResult.VERIFIED_FALSE:
            return False
        else:
            raise ValidationException(
                'Fail to validate cloudant token',
            )

    def resolve_owner(self, secret, other_factors):
        '''
        To be implemented
        '''

        return ''

    def revoke(self, secret, other_factors, secret_id):
        pass
