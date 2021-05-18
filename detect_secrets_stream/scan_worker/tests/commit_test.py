from unittest import TestCase

from detect_secrets_stream.scan_worker.commit import Commit
from detect_secrets_stream.security.security import DeterministicCryptor
from detect_secrets_stream.util.conf import ConfUtil


class CommitTest (TestCase):

    def setUp(self):
        self.test_commit_hash = 'test-commit'
        self.test_branch_name = 'test-branch'
        self.commit = Commit(self.test_commit_hash, 'test-repo', self.test_branch_name)
        self.github_host = ConfUtil.load_github_conf()['host']
        self.test_location_url = f'https://{self.github_host}/test-repo/commit/test-commit'
        self.decryptor = DeterministicCryptor()

    def test_location_url(self):
        self.assertEqual(self.commit.location_url, self.test_location_url)

    def test_encrypt_location_url(self):
        self.assertNotEqual(self.commit.encrypted_location_url, None)
        decrypted_location_url = self.decryptor.decrypt(self.commit.encrypted_location_url)
        self.assertEqual(decrypted_location_url, self.test_location_url)

    def test_encrypt_commit_hash(self):
        self.assertNotEqual(self.commit.encrypted_commit_hash, None)
        decrypted_text = self.decryptor.decrypt(self.commit.encrypted_commit_hash)
        self.assertEqual(decrypted_text, self.test_commit_hash)

    def test_encrypt_branch_name(self):
        self.assertNotEqual(self.commit.encrypted_branch_name, None)
        decrypted_text = self.decryptor.decrypt(self.commit.encrypted_branch_name)
        self.assertEqual(decrypted_text, self.test_branch_name)

    def test_set_branch_name(self):
        old_branch_name = self.commit.branch_name
        old_encrypted_branch_name = self.commit.encrypted_branch_name

        new_branch_name = 'new' + old_branch_name
        self.commit.branch_name = new_branch_name

        assert old_branch_name != self.commit.branch_name
        assert old_encrypted_branch_name != self.commit.encrypted_branch_name

        decrypted_text = self.decryptor.decrypt(self.commit.encrypted_branch_name)
        assert decrypted_text == new_branch_name

    def test_set_commit_hash(self):
        old_commit_hash = self.commit.commit_hash
        old_encrypted_commit_hash = self.commit.encrypted_commit_hash

        new_commit_hash = 'new' + old_commit_hash
        self.commit.commit_hash = new_commit_hash

        assert old_commit_hash != self.commit.commit_hash
        assert old_encrypted_commit_hash != self.commit.encrypted_commit_hash

        decrypted_text = self.decryptor.decrypt(self.commit.encrypted_commit_hash)
        assert decrypted_text == new_commit_hash

    def test_generate_uniqueness_hash(self):
        self.commit.repo_slug = 'test-repo'
        self.commit.branch_name = 'test-branch'
        self.commit.filename = 'test-filename'
        self.commit.linenumber = 1
        self.commit.repo_public = True
        self.commit.generate_uniqueness_hash()

        assert self.commit.uniqueness_hash is not None

    def test_generate_uniqueness_some_fields_none(self):
        self.commit.repo_slug = None
        self.commit.branch_name = None
        self.commit.filename = None
        self.commit.linenumber = 0
        self.commit.repo_public = None
        self.commit.generate_uniqueness_hash()

        assert self.commit.uniqueness_hash is not None

    def test_delete_pi(self):
        self.commit.author_name = 'test-author'
        self.commit.author_email = 'test-author-email'
        self.commit.pusher_username = 'test-pusher-username'
        self.commit.pusher_email = 'test-pusher-email'
        self.commit.committer_name = 'test-committer-name'
        self.commit.committer_email = 'test-committer-email'
        self.commit.repo_slug = 'test-repo-slug'
        self.commit.location_url = 'test-location-url'

        self.commit.delete_pi()

        assert self.commit.author_name == ''
        assert self.commit.author_email == ''
        assert self.commit.pusher_username == ''
        assert self.commit.pusher_email == ''
        assert self.commit.committer_name == ''
        assert self.commit.committer_email == ''
        assert self.commit.repo_slug == ''
        assert self.commit.location_url == ''

        assert self.commit.is_pi_cleaned()

    def test_is_pi_cleaned(self):
        self.commit.author_name = 'test-author'
        self.commit.author_email = 'test-author-email'
        self.commit.pusher_username = 'test-pusher-username'
        self.commit.pusher_email = 'test-pusher-email'
        self.commit.committer_name = 'test-committer-name'
        self.commit.committer_email = 'test-committer-email'
        self.commit.repo_slug = 'test-repo-slug'
        self.commit.location_url = 'test-location-url'

        assert not self.commit.is_pi_cleaned()
        self.commit.author_name = ''
        assert not self.commit.is_pi_cleaned()
        self.commit.author_email = ''
        assert not self.commit.is_pi_cleaned()
        self.commit.pusher_username = ''
        assert not self.commit.is_pi_cleaned()
        self.commit.pusher_email = ''
        assert not self.commit.is_pi_cleaned()
        self.commit.committer_name = ''
        assert not self.commit.is_pi_cleaned()
        self.commit.committer_email = ''
        assert not self.commit.is_pi_cleaned()
        self.commit.repo_slug = ''
        assert not self.commit.is_pi_cleaned()
        self.commit.location_url = ''
        assert self.commit.is_pi_cleaned()

        # None also works
        self.commit.author_name = None
        self.commit.author_email = None
        self.commit.pusher_username = None
        self.commit.pusher_email = None
        self.commit.committer_name = None
        self.commit.committer_email = None
        self.commit.repo_slug = None
        self.commit.location_url = None

        assert self.commit.is_pi_cleaned()
