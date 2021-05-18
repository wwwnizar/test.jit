import logging

from detect_secrets.plugins.box import BoxDetector
from detect_secrets.plugins.box import get_box_user

from detect_secrets_stream.validation.base import BaseValidator


class BoxValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return BoxDetector.secret_type

    def validate(self, secret, other_factors) -> bool:
        clientid = self.get_key_from_other_factors('clientID', other_factors)
        publickeyid = self.get_key_from_other_factors('publicKeyID', other_factors)
        privatekey = self.get_key_from_other_factors('privateKey', other_factors)
        passphrase = self.get_key_from_other_factors('passphrase', other_factors)
        enterpriseid = self.get_key_from_other_factors('enterpriseID', other_factors)

        result = get_box_user(
            clientid, secret, enterpriseid,
            publickeyid, passphrase, privatekey,
        )
        if result:
            return True
        else:
            return False

    def resolve_owner(self, secret, other_factors):
        """ Returns the user name registered in box for the credentials.
            If this can't be retrieved, returns empty string. """
        clientid = self.get_key_from_other_factors('clientID', other_factors)
        publickeyid = self.get_key_from_other_factors('publicKeyID', other_factors)
        privatekey = self.get_key_from_other_factors('privateKey', other_factors)
        passphrase = self.get_key_from_other_factors('passphrase', other_factors)
        enterpriseid = self.get_key_from_other_factors('enterpriseID', other_factors)

        owner = get_box_user(
            clientid, secret, enterpriseid,
            publickeyid, passphrase, privatekey,
        )
        if owner:
            return owner
        else:
            return ''

    def revoke(self, secret, other_factors, secret_id):
        pass
