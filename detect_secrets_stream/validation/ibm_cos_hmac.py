import logging
import re
import xml.etree.ElementTree as ElementTree

from detect_secrets.plugins.ibm_cos_hmac import IbmCosHmacDetector
from detect_secrets.plugins.ibm_cos_hmac import query_ibm_cos_hmac
from detect_secrets.plugins.ibm_cos_hmac import verify_ibm_cos_hmac_credentials

from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class IBMCosHmacValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return IbmCosHmacDetector.secret_type

    def get_access_key_id(self, other_factors):
        return self.get_key_from_other_factors('access_key_id', other_factors)

    def validate(self, secret, other_factors):
        access_key_id = self.get_access_key_id(other_factors)
        try:
            return verify_ibm_cos_hmac_credentials(access_key_id, secret)
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException(
                'Failed to validate IBM Cloud Object Storage HMAC token.',
            )

    def resolve_owner(self, secret, other_factors):
        """ If token is valid, returns a json formatted string containing the
        user's...

        1. ID for service ID
        """
        access_key_id = self.get_access_key_id(other_factors)

        try:
            response = query_ibm_cos_hmac(access_key_id, secret)
            if response.status_code != 200:
                return ''

            root = ElementTree.fromstring(response.text)

            # get namespace
            namespace = re.search(r'\{.*\}', root.tag)[0]
            service_ids = root.findall(f'.//{namespace}DisplayName')
            if service_ids:
                return service_ids[0].text

            return ''

        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException(
                'Failed to resolve owner for IBM Cloud Object Storage HMAC token.',
            )

    def revoke(self, secret, other_factors, secret_id):
        pass
