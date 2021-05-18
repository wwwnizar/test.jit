import datetime
import json
import os
import uuid

from ..gd_revoker.revocation_exception import RevocationException
from ..secret_corpus_db.vault import Vault
from ..secret_corpus_db.vault_read_exception import VaultReadException
from ..security.security import DeterministicCryptor
from ..security.security import Encryptor
from ..validation.email_filter import EmailFilter
from ..validation.factory import ValidatorFactory
from ..validation.validateException import ValidationException
from .hasher import Hasher


class Secret(object):

    def __init__(self, secret, secret_type):
        self._id = None
        self._comment = None
        self._first_identified = None
        self._live = None
        self._last_test_date = None
        self._last_test_success = None
        self._secret = secret
        self._secret_type = secret_type
        self._diff_file_linenumber = None
        self._filename = None
        self._linenumber = None
        self._other_factors = None
        self._encrypted_secret = None
        self._encrypted_other_factors = None
        self._hashed_secret = None
        self._uuid = str(uuid.uuid4())
        self._owner_email = None
        self._remediation_date = None
        self.validator = ValidatorFactory.get_validator(self.secret_type)

        self.encryptor = Encryptor()
        self.determ_encryptor = DeterministicCryptor()
        self.hasher = Hasher(os.getenv('GD_HMAC_KEY_FILENAME'))

        self._encrypted_secret = self.non_deterministic_encrypt(self._secret)
        self.generate_hashed_secret()

    @property
    def secret(self):
        return self._secret

    @property
    def secret_type(self):
        return self._secret_type

    @property
    def diff_file_linenumber(self):
        return self._diff_file_linenumber

    @property
    def filename(self):
        return self._filename

    @property
    def linenumber(self):
        return self._linenumber

    @property
    def other_factors(self):
        return self._other_factors

    @property
    def encrypted_secret(self):
        return self._encrypted_secret

    @property
    def encrypted_other_factors(self):
        return self._encrypted_other_factors

    @property
    def hashed_secret(self):
        return self._hashed_secret

    @property
    def uuid(self):
        return self._uuid

    @property
    def owner_email(self):
        return self._owner_email

    @property
    def remediation_date(self):
        return self._remediation_date

    @property
    def id(self):
        return self._id

    @property
    def comment(self):
        return self._comment

    @property
    def first_identified(self):
        return self._first_identified

    @property
    def live(self):
        return self._live

    @property
    def last_test_date(self):
        return self._last_test_date

    @property
    def last_test_success(self):
        return self._last_test_success

    @id.setter
    def id(self, value: int):
        self._id = value

    @secret.setter
    def secret(self, value: str):
        if self._secret != value:
            self._secret = value
            self._encrypted_secret = self.non_deterministic_encrypt(value)
            self.generate_hashed_secret()

    @comment.setter
    def comment(self, value: str):
        self._comment = value

    @first_identified.setter
    def first_identified(self, value: str):
        self._first_identified = value

    @live.setter
    def live(self, value: str):
        self._live = value

    @last_test_date.setter
    def last_test_date(self, value: str):
        self._last_test_date = value

    @last_test_success.setter
    def last_test_success(self, value: str):
        self._last_test_success = value

    @encrypted_secret.setter
    def encrypted_secret(self, value: str):
        self._encrypted_secret = value

    @encrypted_other_factors.setter
    def encrypted_other_factors(self, value: str):
        self._encrypted_other_factors = value

    @hashed_secret.setter
    def hashed_secret(self, value: str):
        self._hashed_secret = value

    @diff_file_linenumber.setter
    def diff_file_linenumber(self, value: int):
        self._diff_file_linenumber = value

    @filename.setter
    def filename(self, value: str):
        self._filename = value

    @linenumber.setter
    def linenumber(self, value: int):
        self._linenumber = value

    @other_factors.setter
    def other_factors(self, value: dict):
        if self._other_factors != value:
            self._other_factors = value
            self._encrypted_other_factors = self.non_deterministic_encrypt(json.dumps(value))
            self.generate_hashed_secret()

    @uuid.setter
    def uuid(self, value: str):
        self._uuid = value

    @owner_email.setter
    def owner_email(self, value: str):
        self._owner_email = value

    @remediation_date.setter
    def remediation_date(self, value: datetime.datetime):
        self._remediation_date = value

    def non_deterministic_encrypt(self, raw_data: str):
        """
        Accepts: string, unencrypted data
        Returns: string, encrypted data (using pkcs1Cipher)
        """
        return self.encryptor.encrypt(raw_data)

    def deterministic_encrypt(self, raw_data: str):
        """
        Accepts: string, unencrypted data
        Returns: string, encrypted data (using pkcs1Cipher)
        """
        return self.determ_encryptor.encrypt(raw_data)

    def read_secret_from_vault(self):
        """
        Sets self.secret and self.other_factors from vault.
        Can throw a VaultReadException if secret doesn't exist in vault or if id isn't set.
        Should call from try, except block.
        """
        if not self.id:
            raise VaultReadException("id not set for secret. Can't retrieve from vault.")

        vault = Vault()
        try:
            data = vault.read_secret(self.id)
        except Exception:
            raise VaultReadException('Error reading secret from vault. Secret might not be in vault')
        else:
            self.secret = data['secret']
            self.other_factors = data['other_factors']

    def lookup_token_owner(self, filter_out_external=True):
        if self.validator:
            owner = self.validator.resolve_owner(self.secret, self.other_factors)

            if filter_out_external:
                self._owner_email = EmailFilter().filter_external_emails(owner)
            else:
                self._owner_email = owner

            if self._owner_email is None:
                self._owner_email = ''

        return self._owner_email

    def verify(self):
        if self.validator:
            return self.validator.validate(self.secret, self.other_factors)
        else:
            raise ValidationException(f'Can not validate for unknown token type "{self.secret_type}')

    def revoke(self):
        if self.validator:
            return self.validator.revoke(self.secret, self.other_factors, self.id)
        else:
            raise RevocationException(f'Can not revoke for unknown token type "{self.secret_type}"')

    def generate_hashed_secret(self):
        self._hashed_secret = self.hasher.hash(
            ';'.join(
                [
                    str(self._secret) if self._secret else '',
                    json.dumps(self._other_factors) if self._other_factors else '',
                ],
            ),
        )

    def is_ready_for_vault_insert(self):
        """ Checks that all expected fields used in vault write are populated.
        Returns bool indicating if the Secret object is ready. """
        ready = self._secret is not None and \
            self._id is not None

        return ready

    def is_ready_for_revalidated_db_update(self):
        """ Checks that all expected fields used in DB write are populated.
        Returns bool indicating if the Secret object is ready. """
        ready = self._last_test_date is not None and \
            self._live is not None and  \
            self._first_identified is not None

        remediation_date_ready = False
        if self._live:
            remediation_date_ready = True
        else:
            remediation_date_ready = self._remediation_date is not None

        return ready and remediation_date_ready

    def delete_pi(self):
        """ Remove fields designated as PI (personal information) """
        self._owner_email = ''
        self._secret = ''
        self._encrypted_secret = ''
        self._other_factors = ''
        self._hashed_secret = ''

    def is_pi_cleaned(self):
        """ Checks that PI fields have been set to empty strings. """
        ready = (self._owner_email == '' or self._owner_email is None) and \
            (self._secret == '' or self._secret is None) and \
            (self._hashed_secret == '' or self._hashed_secret is None) and \
            (self._encrypted_secret == '' or self._encrypted_secret is None) and \
            (self._other_factors == '' or self._other_factors is None)

        return ready
