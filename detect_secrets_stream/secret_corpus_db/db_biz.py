import json
import logging

from ..scan_worker.commit import Commit
from ..scan_worker.secret import Secret
from ..secret_corpus_db.gd_db_tools import add_token_row
from ..secret_corpus_db.gd_db_tools import connect_db
from ..secret_corpus_db.gd_db_tools import get_all_tokens
from ..secret_corpus_db.gd_db_tools import get_commits
from ..secret_corpus_db.gd_db_tools import get_commits_by_token_id
from ..secret_corpus_db.gd_db_tools import get_live_tokens
from ..secret_corpus_db.gd_db_tools import get_remediated_tokens
from ..secret_corpus_db.gd_db_tools import get_token_by_id
from ..secret_corpus_db.gd_db_tools import get_token_by_uuid
from ..secret_corpus_db.gd_db_tools import update_commit_by_commit_id
from ..secret_corpus_db.gd_db_tools import update_token_by_id
from ..secret_corpus_db.vault import Vault
from ..secret_corpus_db.vault_read_exception import VaultReadException
from ..security.security import Decryptor
from ..security.security import DeterministicCryptor


class DbBiz:
    def __init__(self, *args, **kwargs):
        self.conn = None
        self.decrypter = None
        self.vault = Vault()
        self.logger = logging.getLogger(__name__)

    def get_decrypter(self):
        if not self.decrypter:
            self.decrypter = Decryptor()
        return self.decrypter

    def decrypt(self, encrypted_text: str) -> str:
        return self.get_decrypter().decrypt(encrypted_text)

    def get_conn(self):
        if not self.conn:
            self.conn = connect_db()
        return self.conn

    def get_live_tokens(self):
        '''
        Get all live tokens by id
        '''
        conn = self.get_conn()
        return get_live_tokens(conn)

    def get_remediated_tokens_from_db(self):
        '''
        Get all remediated tokens by id
        '''
        conn = self.get_conn()
        return get_remediated_tokens(conn)

    def get_all_tokens(self):
        '''
        Get all tokens by id
        '''
        conn = self.get_conn()
        return get_all_tokens(conn)

    def token_to_secret(self, token) -> Secret:
        token_id, \
            token_cred_enc, \
            token_comment, \
            token_type, \
            first_identified, \
            is_live, \
            last_test_date, \
            last_test_success, \
            token_hash, \
            other_factors_enc, \
            uuid, \
            owner_email, \
            remediation_date = (
                token
            )

        # get secret from vault
        try:
            self.logger.info(f'Getting token_id={token_id} from vault')
            vault_data = self.vault.read_secret(token_id)
            token_cred = vault_data['secret']
            other_factors = vault_data['other_factors']
        except VaultReadException:
            self.logger.info(f'Getting token_id={token_id} from database')
            token_cred = self.decrypt(token_cred_enc)
            other_factors = self.decrypt(other_factors_enc)

        secret = Secret(token_cred, token_type)
        secret.id = token_id
        if token_cred_enc:
            secret.encrypted_secret = token_cred_enc.tobytes()
        secret.comment = token_comment
        secret.first_identified = first_identified
        secret.live = is_live
        secret.last_test_date = last_test_date
        secret.last_test_success = last_test_success
        if other_factors:
            try:
                secret.other_factors = json.loads(other_factors)
            except (json.decoder.JSONDecodeError, TypeError):
                secret.other_factors = other_factors
        if other_factors_enc:
            secret.encrypted_other_factors = other_factors_enc.tobytes()
        secret.hashed_secret = token_hash
        secret.uuid = uuid
        secret.owner_email = owner_email
        secret.remediation_date = remediation_date

        return secret

    def row_to_commit(self, row) -> Commit:
        ''' converts a raw DB row to a commit object '''
        commit_id, encrypted_commit_hash, repo_slug, encrypted_branch_name, \
            encrypted_location_url, author_name, author_email, pusher_username, \
            pusher_email, committer_name, committer_email, repo_public, \
            uniqueness_hash, encrypted_filename, encrypted_linenumber, token_id = (row)

        deterministic_decrypter = DeterministicCryptor()
        commit_hash = deterministic_decrypter.decrypt(encrypted_commit_hash)
        branch_name = deterministic_decrypter.decrypt(encrypted_branch_name)
        location_url = deterministic_decrypter.decrypt(encrypted_location_url)
        filename = deterministic_decrypter.decrypt(encrypted_filename)
        linenumber = deterministic_decrypter.decrypt(encrypted_linenumber)

        commit = Commit(
            commit_hash,
            repo_slug,
            branch_name,
        )
        commit.author_name = author_name
        commit.author_email = author_email
        commit.pusher_username = pusher_username
        commit.pusher_email = pusher_email
        commit.committer_name = committer_name
        commit.committer_email = committer_email
        commit.uniqueness_hash = uniqueness_hash
        commit.location_url = location_url
        commit.filename = filename
        commit.commit_id = commit_id
        commit.repo_public = repo_public
        commit.token_id = token_id
        commit.linenumber = linenumber

        return commit

    def get_secret_from_db(self, token_id: str) -> Secret:
        '''
        Get secret from db based on id
        '''
        if not token_id:
            return None

        conn = self.get_conn()
        tokens = get_token_by_id(conn, token_id)
        if not tokens:
            return None

        return self.token_to_secret(tokens[0])

    def get_commits_by_token_id_from_db(self, token_id: str) -> [Commit]:
        ''' Get list of Commit objects associated with the token_id '''
        conn = self.get_conn()
        rows = get_commits_by_token_id(conn, token_id)
        if not rows:
            return []

        commits = []
        for row in rows:
            commit = self.row_to_commit(row)
            commits.append(commit)

        return commits

    def get_secret_from_db_by_uuid(self, token_uuid: str) -> Secret:
        '''
        Get secret from db based on uuid
        '''
        if not token_uuid:
            return None

        conn = self.get_conn()
        tokens = get_token_by_uuid(conn, token_uuid)
        if not tokens:
            return None

        return self.token_to_secret(tokens[0])

    def write_secret_to_db(self, secret: Secret) -> str:
        '''
        Write secret to db

        Return secret_id
        '''
        if not secret:
            return None

        return_id = None
        if secret.id:  # update
            return_id = update_token_by_id(
                self.get_conn(),
                token_id=secret.id,
                token_cred=None,
                token_comment=secret.comment,
                token_type=secret.secret_type,
                first_identified=secret.first_identified,
                is_live=secret.live,
                last_test_date=secret.last_test_date,
                last_test_success=secret.last_test_success,
                other_factors=None,
                uuid=secret.uuid,
                token_hash=secret.hashed_secret,
                owner_email=secret.owner_email,
                remediation_date=secret.remediation_date,
            )
            self.vault.create_or_update_secret(secret.id, secret.secret, secret.other_factors)
        else:  # insert
            return_id = add_token_row(
                self.get_conn(),
                token_cred=None,
                token_type=secret.secret_type,
                token_comment=secret.comment,
                other_factors=None,
                uuid=secret.uuid,
                is_live=secret.live,
                token_hash=secret.hashed_secret,
                owner_email=secret.owner_email,
                remediation_date=secret.remediation_date,
            )
            self.vault.create_or_update_secret(return_id, secret.secret, secret.other_factors)

        return return_id

    def update_commit_in_db(self, commit: Commit):
        '''
        Write update pusher, author, committer info in db
        '''
        if not commit:
            return False

        conn = self.get_conn()
        update_commit_by_commit_id(
            conn, commit.commit_id,  commit.encrypted_commit_hash,
            commit.repo_slug, commit.encrypted_branch_name,
            commit.encrypted_location_url, commit.pusher_username, commit.pusher_email,
            commit.author_name, commit.author_email, commit.committer_name,
            commit.committer_email, commit.repo_public, commit.uniqueness_hash,
            commit.encrypted_filename, commit.encrypted_linenumber, commit.token_id,
        )
        return True

    def get_all_commits_from_db(self):
        conn = self.get_conn()
        rows = get_commits(conn)
        if not rows:
            return []

        commits = []
        for row in rows:
            commit = self.row_to_commit(row)
            commits.append(commit)

        return commits
