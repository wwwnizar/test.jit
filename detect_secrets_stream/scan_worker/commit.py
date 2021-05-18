import os

from ..security.security import DeterministicCryptor
from ..util.conf import ConfUtil
from .hasher import Hasher


class Commit(object):

    def __init__(self, commit_hash, repo_slug, branch_name):
        self._commit_hash = commit_hash
        self._repo_slug = repo_slug
        self._branch_name = branch_name
        self._github_host = ConfUtil.load_github_conf()['host']
        self._location_url = f'https://{self._github_host}/{repo_slug}/commit/{commit_hash}'
        self._author_name = None
        self._author_email = None
        self._pusher_username = None
        self._pusher_email = None
        self._committer_name = None
        self._committer_email = None
        self._repo_public = None
        self._commit_id = None
        self._filename = None
        self._linenumber = None
        self._token_id = None

        self.encryptor = DeterministicCryptor()
        self._encrypted_location_url = self.encrypt(self._location_url)
        self._encrypted_commit_hash = self.encrypt(self._commit_hash)
        self._encrypted_branch_name = self.encrypt(self._branch_name)
        self._encrypted_filename = self.encrypt(self._filename)
        self._encrypted_linenumber = self.encrypt(self._linenumber)

        self.hasher = Hasher(os.getenv('GD_HMAC_KEY_FILENAME'))
        self._uniqueness_hash = None

    @property
    def commit_hash(self):
        return self._commit_hash

    @property
    def repo_slug(self):
        return self._repo_slug

    @property
    def branch_name(self):
        return self._branch_name

    @property
    def author_name(self):
        return self._author_name

    @property
    def author_email(self):
        return self._author_email

    @property
    def pusher_username(self):
        return self._pusher_username

    @property
    def pusher_email(self):
        return self._pusher_email

    @property
    def committer_name(self):
        return self._committer_name

    @property
    def committer_email(self):
        return self._committer_email

    @property
    def location_url(self):
        return self._location_url

    @property
    def encrypted_location_url(self):
        return self._encrypted_location_url

    @property
    def encrypted_commit_hash(self):
        return self._encrypted_commit_hash

    @property
    def encrypted_branch_name(self):
        return self._encrypted_branch_name

    @property
    def repo_public(self):
        return self._repo_public

    @property
    def commit_id(self):
        return self._commit_id

    @property
    def uniqueness_hash(self):
        return self._uniqueness_hash

    @property
    def filename(self):
        return self._filename

    @property
    def linenumber(self):
        return self._linenumber

    @property
    def encrypted_filename(self):
        return self._encrypted_filename

    @property
    def encrypted_linenumber(self):
        return self._encrypted_linenumber

    @property
    def token_id(self):
        return self._token_id

    @author_name.setter
    def author_name(self, name: str):
        self._author_name = name

    @author_email.setter
    def author_email(self, email: str):
        self._author_email = email

    @pusher_username.setter
    def pusher_username(self, username: str):
        self._pusher_username = username

    @pusher_email.setter
    def pusher_email(self, email: str):
        self._pusher_email = email

    @committer_name.setter
    def committer_name(self, name: str):
        self._committer_name = name

    @committer_email.setter
    def committer_email(self, email: str):
        self._committer_email = email

    @location_url.setter
    def location_url(self, value: str):
        if self._location_url != value:
            self._encrypted_location_url = self.encrypt(value)
        self._location_url = value

    @commit_hash.setter
    def commit_hash(self, value: str):
        if self._commit_hash != value:
            self._encrypted_commit_hash = self.encrypt(value)
        self._commit_hash = value

    @branch_name.setter
    def branch_name(self, value: str):
        if self._branch_name != value:
            self._encrypted_branch_name = self.encrypt(value)
        self._branch_name = value

    @encrypted_location_url.setter
    def encrypted_location_url(self, encrypted_url: str):
        self._encrypted_location_url = encrypted_url

    @repo_public.setter
    def repo_public(self, repo_public: bool):
        self._repo_public = repo_public

    @commit_id.setter
    def commit_id(self, commit_id: int):
        if commit_id is not None:
            self._commit_id = int(commit_id)
        else:
            self._commit_id = None

    @repo_slug.setter
    def repo_slug(self, repo_slug: str):
        self._repo_slug = repo_slug

    @filename.setter
    def filename(self, filename: str):
        self._filename = filename
        self._encrypted_filename = self.encrypt(self._filename)

    @linenumber.setter
    def linenumber(self, linenumber: int):
        if linenumber is not None:
            self._linenumber = int(linenumber)
            self._encrypted_linenumber = self.encrypt(str(self._linenumber))
        else:
            self._linenumber = None
            self._encrypted_linenumber = None

    @token_id.setter
    def token_id(self, token_id: int):
        if token_id is not None:
            self._token_id = int(token_id)
        else:
            self._token_id = None

    @uniqueness_hash.setter
    def uniqueness_hash(self, uniqueness_hash: str):
        self._uniqueness_hash = uniqueness_hash

    def encrypt(self, raw_data: str):
        """
        Accepts: string, unencrypted data
        Returns: string, encrypted data (using pkcs1Cipher)
        """
        return self.encryptor.encrypt(raw_data)

    def generate_uniqueness_hash(self):
        """ Hash used to distinguish a unique commit containing a secret in
        some specific location. """
        self._uniqueness_hash = self.hasher.hash(
            ';'.join(
                [
                    str(self._token_id) if self._token_id else '',
                    str(self._commit_hash) if self._commit_hash else '',
                    str(self._repo_slug) if self._repo_slug else '',
                    str(self._branch_name) if self._branch_name else '',
                    str(self._filename) if self._filename else '',
                    str(self._linenumber) if self._linenumber else '',
                    str(self._repo_public) if self._repo_public is not None else '',
                ],
            ),
        )

    def delete_pi(self):
        """ Remove fields designated as PI (personal information) """
        self._author_name = ''
        self._author_email = ''
        self._pusher_username = ''
        self._pusher_email = ''
        self._committer_name = ''
        self._committer_email = ''
        self._repo_slug = ''
        self._location_url = ''

    def is_pi_cleaned(self):
        """ Checks that PI fields have been set to empty strings. """
        ready = (self._author_name == '' or self._author_name is None) and \
            (self._author_email == '' or self._author_email is None) and \
            (self._pusher_username == '' or self._pusher_username is None) and \
            (self._pusher_email == '' or self._pusher_email is None) and \
            (self._committer_name == '' or self._committer_name is None) and \
            (self._committer_email == '' or self._committer_email is None) and \
            (self._repo_slug == '' or self._repo_slug is None) and \
            (self._location_url == '' or self._location_url is None)

        return ready
