import logging

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.db2 import Db2Detector
from detect_secrets.plugins.db2 import verify_db2_credentials

from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class DB2Validator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return Db2Detector.secret_type

    def validate(self, secret, other_factors) -> bool:
        database = self.get_key_from_other_factors('database', other_factors)
        hostname = self.get_key_from_other_factors('hostname', other_factors)
        port = self.get_key_from_other_factors('port', other_factors)
        username = self.get_key_from_other_factors('username', other_factors)
        password = secret

        result = verify_db2_credentials(database, hostname, port, username, password)
        if result == VerifiedResult.VERIFIED_TRUE:
            return True
        elif result == VerifiedResult.VERIFIED_FALSE:
            return False
        else:
            raise ValidationException(
                'Failed to validate DB2 token. '
                f'{result} is neither VERIFIED_TRUE or VERIFIED_FALSE.',
            )

    def resolve_owner(self, secret, other_factors):
        """ Returns the database username captured in other_factors. """
        return self.get_key_from_other_factors('username', other_factors)

    def revoke(self, secret, other_factors, secret_id):
        pass
