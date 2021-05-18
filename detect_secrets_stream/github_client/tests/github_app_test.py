from unittest import TestCase

import pytest
import responses
from mock import patch
from requests.exceptions import HTTPError

from detect_secrets_stream.github_client.github import GitHub
from detect_secrets_stream.github_client.github_app import GitHubApp
from detect_secrets_stream.github_client.installation_id_request_exception import InstallationIDRequestException
from detect_secrets_stream.util.conf import ConfUtil


class TestGitHubApp(TestCase):

    def setUp(self):
        self.github_app = GitHubApp(jwt_ttl_minutes=0)
        self.initial_app_github = self.github_app._app_github
        self.github_host = ConfUtil.load_github_conf()['host']
        assert self.initial_app_github is not None

    def test_refresh_jwt_token(self):
        self.github_app._refresh_jwt_token()
        # check that expire time has been updated and github client re-initialized
        assert self.github_app._app_github != self.initial_app_github

    @responses.activate
    def test_get_repo_installation_id(self):
        repo = 'fake-org/fake-repo'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{repo}/installation',
            status=200,
            body='{"id": 1}',
        )
        id = self.github_app._get_installation_id(repo)
        assert id == 1

    @responses.activate
    def test_get_repo_installation_id_bad_request(self):
        repo = 'fake-org/fake-repo'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{repo}/installation',
            status=404,
        )
        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(repo)

    @responses.activate
    def test_get_repo_installation_id_no_id(self):
        repo = 'fake-org/fake-repo'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/repos/{repo}/installation',
            status=200,
            body='{"not_id": 1}',
        )
        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(repo)

    @responses.activate
    def test_get_org_installation_id(self):
        org = 'fake-org'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{org}',
            status=200, body='{"type":"Organization"}',
        )
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/orgs/{org}/installation', status=200, body='{"id": 1}',
        )
        id = self.github_app._get_installation_id(org)
        assert id == 1

    @responses.activate
    def test_get_org_installation_id_bad_request(self):
        org = 'fake-org'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{org}',
            status=200,
            body='{"type":"Organization"}',
        )
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/orgs/{org}/installation',
            status=404,
        )
        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(org)

    @responses.activate
    def test_get_org_installation_id_no_id(self):
        org = 'fake-org'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{org}',
            status=200, body='{"type":"Organization"}',
        )
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/orgs/{org}/installation',
            status=200, body='{"not_id": 1}',
        )
        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(org)

    @responses.activate
    def test_get_org_installation_id_user(self):
        user = 'fake-user'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{user}',
            status=200, body='{"type":"User"}',
        )
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{user}/installation',
            status=200, body='{"id": 1}',
        )

        id = self.github_app._get_installation_id(user)
        assert id == 1

    @responses.activate
    def test_get_org_installation_id_user_fails_no_id(self):
        user = 'fake-user'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{user}',
            status=200, body='{"type":"User"}',
        )
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{user}/installation',
            status=200, body='{"not_id": 1}',
        )

        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(user)

    @responses.activate
    def test_get_org_installation_id_user_fails_bad_request_first_call(self):
        user = 'fake-user'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{user}',
            status=404,
        )

        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(user)

    @responses.activate
    def test_get_org_installation_id_user_fails_bad_request_second_call(self):
        user = 'fake-user'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{user}',
            status=200, body='{"type":"User"}',
        )
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{user}/installation',
            status=404,
        )

        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(user)

    @responses.activate
    def test_get_org_installation_id_user_fails_unexpected_type(self):
        org = 'fake-org'
        responses.add(
            responses.GET, f'https://{self.github_host}/api/v3/users/{org}',
            status=200, body='{"type":"Dolphin"}',
        )

        with pytest.raises(InstallationIDRequestException):
            self.github_app._get_installation_id(org)

    @responses.activate
    def test_create_installation_token(self):
        installation_id = 1
        responses.add(
            responses.POST, f'https://{self.github_host}/api/v3/app/installations/{installation_id}/access_tokens',
            status=200, body='{"token": "test-token"}',
        )
        token = self.github_app._create_installation_token(installation_id)
        assert token == 'test-token'

    @responses.activate
    def test_create_installation_token_bad_request(self):
        installation_id = 1
        responses.add(
            responses.POST, f'https://{self.github_host}/api/v3/app/installations/{installation_id}/access_tokens',
            status=404,
        )
        with pytest.raises(HTTPError, match=r'404 .*'):
            self.github_app._create_installation_token(installation_id)

    @responses.activate
    def test_create_installation_token_no_token(self):
        installation_id = 1
        responses.add(
            responses.POST, f'https://{self.github_host}/api/v3/app/installations/{installation_id}/access_tokens',
            status=200, body='{"not_token": 1}',
        )
        with pytest.raises(Exception):
            self.github_app._create_installation_token(installation_id)

    @patch('detect_secrets_stream.github_client.github_app.GitHubApp._create_installation_token')
    @patch('detect_secrets_stream.github_client.github_app.GitHubApp._get_installation_id')
    def test_get_github_client(self, mock_get_install_id, mock_create_install_token):
        mock_get_install_id.return_value = 1

        org = 'fake-org'

        github = self.github_app.get_github_client(org)
        assert github is not None
        assert type(github) is GitHub
        mock_get_install_id.assert_called_with(org)
        mock_create_install_token.assert_called_with(1)

        repo = 'fake-org/fake-repo'

        github = self.github_app.get_github_client(repo)
        assert github is not None
        assert type(github) is GitHub
        mock_get_install_id.assert_called_with(repo)
        mock_create_install_token.assert_called_with(1)
