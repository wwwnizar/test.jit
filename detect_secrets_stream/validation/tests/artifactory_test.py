import pytest
import responses
from detect_secrets.core.constants import VerifiedResult
from mock import patch

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.scan_worker.commit import Commit
from detect_secrets_stream.util.conf import ConfUtil
from detect_secrets_stream.validation.artifactory import ArtifactoryValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestArtifactoryValidator:

    revocation_endpoint = ConfUtil.load_revoker_urls_conf()['artifactory-revocation']
    owner_resolution_endpoint = ConfUtil.load_revoker_urls_conf()['artifactory-owner-resolution']

    @pytest.mark.parametrize(
        'result, expected_valid',
        [
            (VerifiedResult.VERIFIED_TRUE, True),
            (VerifiedResult.VERIFIED_FALSE, False),
        ],
    )
    @patch('detect_secrets.plugins.artifactory.ArtifactoryDetector.verify')
    def test_validate_artifactory_token(self, mock_verify, result, expected_valid):
        mock_verify.return_value = result
        artifactory_validator = ArtifactoryValidator()
        valid = artifactory_validator.validate('test-token')
        assert valid is expected_valid

    @patch('detect_secrets.plugins.artifactory.ArtifactoryDetector.verify')
    def test_validate_artifactory_token_unverifiable(self, mock_verify):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        artifactory_validator = ArtifactoryValidator()
        with pytest.raises(ValidationException):
            artifactory_validator.validate('test-token')

    @responses.activate
    def test_resolve_owner_response_email(self):
        email = 'my@email.com'
        responses.add(
            responses.GET, self.owner_resolution_endpoint,
            body=f'something = else\nemail = {email}', status=200,
        )
        validator = ArtifactoryValidator()
        owner = validator.resolve_owner('password')
        assert owner == email

    @pytest.mark.parametrize(
        'payload',
        [
            None,
            '',
            'wrong\nformat',
            'wrong format',
        ],
    )
    @responses.activate
    def test_resolve_owner_response_email_wrong_payload(self, payload):
        responses.add(
            responses.GET, self.owner_resolution_endpoint,
            body=payload, status=200,
        )
        validator = ArtifactoryValidator()
        owner = validator.resolve_owner('password')
        assert owner == ''

    @responses.activate
    def test_resolve_owner_response_error(self):
        responses.add(
            responses.GET, self.owner_resolution_endpoint,
            body='', status=400,
        )
        validator = ArtifactoryValidator()
        with pytest.raises(ValidationException):
            validator.resolve_owner('password')

    @responses.activate
    def test_revoke_artifactory_token(self):
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=200,
            json={'revoked': True},
        )
        artifactory_validator = ArtifactoryValidator()
        result = artifactory_validator.revoke('test-secret')
        assert result is True

    @responses.activate
    @patch('detect_secrets_stream.validation.artifactory.DbBiz')
    def test_revoke_artifactory_token_with_location_urls(self, mock_db):
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=200,
            json={'revoked': True},
        )
        test_commit_1 = Commit('test-hash-1', 'test-repo-1', 'test-branch-1')
        test_commit_2 = Commit('test-hash-2', 'test-repo-2', 'test-branch-2')
        mock_db.return_value.get_commits_by_token_id_from_db.return_value = \
            [test_commit_1, test_commit_2]

        artifactory_validator = ArtifactoryValidator()
        result = artifactory_validator.revoke('test-secret', secret_id=1)

        mock_db.return_value.get_commits_by_token_id_from_db.assert_called_with(1)
        assert result is True

    @responses.activate
    def test_revoke_artifactory_token_revoked_false(self):
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=200,
            json={'revoked': False},
        )
        artifactory_validator = ArtifactoryValidator()
        result = artifactory_validator.revoke('test-secret')
        assert result is False

    @responses.activate
    def test_revoke_artifactory_token_server_error(self):
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=500,
            json={'revoked': False},
        )
        artifactory_validator = ArtifactoryValidator()
        with pytest.raises(RevocationException):
            artifactory_validator.revoke('test-secret')

    @responses.activate
    def test_revoke_unexpected_payload(self):
        responses.add(
            responses.POST,
            self.revocation_endpoint,
            status=200,
            json={'not-the-expected-field': True},
        )
        artifactory_validator = ArtifactoryValidator()
        with pytest.raises(RevocationException):
            artifactory_validator.revoke('test-secret')
