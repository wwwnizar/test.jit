import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac


class Hasher(object):

    def __init__(self, hmac_key_filename):
        if not os.path.isfile(hmac_key_filename):
            raise Exception(f'hmac_key_filename={hmac_key_filename} is not a regualar file')

        with open(hmac_key_filename, mode='rb') as hmac_file:
            self.hmac_key = hmac_file.read()

    def hash(self, raw_data: str):
        """
        Accepts: string, unhashed data
        Returns: string, hashed data (using an hmac with a sha256 hash algorithm)
        """
        if not raw_data:
            return ''
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(str.encode(raw_data))
        return h.finalize().hex()
