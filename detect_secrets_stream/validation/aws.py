import logging

from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.aws import verify_aws_secret_access_key

from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class AWSValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return AWSKeyDetector.secret_type

    def get_secret_access_key(self, other_factors):
        return self.get_key_from_other_factors('secret_access_key', other_factors)

    def validate(self, secret, other_factors=None):
        access_key = secret
        secret_access_key = self.get_secret_access_key(other_factors)

        try:
            return verify_aws_secret_access_key(access_key, secret_access_key)
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException(
                'Failed to validate AWS token.',
            )

    def resolve_owner(self, secret, other_factors=None):
        """
        Not implemented due to GPA restirction. We should not resolve owner
        from 3rd party services.
        """
        return ''

    def revoke(self, secret, other_factors, secret_id):
        pass
