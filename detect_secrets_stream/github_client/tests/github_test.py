import json

import pytest
import requests
import responses
from mock import patch

from detect_secrets_stream.github_client.github import GitHub
from detect_secrets_stream.util.conf import ConfUtil


class TestGithub ():

    github_host = ConfUtil.load_github_conf()['host']

    @pytest.fixture
    def test_github(self):
        token_list = ['token1', 'token2', 'token3']
        min_remaining_rate_limit = 3
        return GitHub(token_list, min_remaining_rate_limit)

    @pytest.fixture(scope='module')
    def graphql_payload(self):
        return {
            'data': {
                'node': {
                    'history': {
                        'totalCount': 4,
                        'pageInfo': {'endCursor': 1},
                        'edges': [
                            {'node': {'oid': 2}},
                            {'node': {'oid': 1}},
                        ],
                    },
                },
            },
        }

    def test_get_auth_header(self, test_github):
        old_token = test_github.token = None
        header = test_github._get_auth_header()
        assert old_token != test_github.token
        assert header == {'Authorization': 'bearer %s' % (test_github.token)}

        old_token = test_github.token
        header = test_github._get_auth_header()
        assert old_token == test_github.token
        assert header == {'Authorization': 'bearer %s' % (test_github.token)}

        test_github.auth_header_type = 'token'
        header = test_github._get_auth_header()
        assert header == {'Authorization': 'token %s' % (test_github.token)}

    def test_rotate_token(self, test_github):
        """ [GitHub] rotateToken """
        old_token = test_github.token
        test_github._rotate_token()
        assert old_token != test_github.token

        old_token = test_github.token
        test_github._rotate_token(
            response=responses.HTTPResponse(
                headers={'X-RateLimit-Remaining': '1'},
            ),
        )
        assert old_token != test_github.token

        old_token = test_github.token
        test_github._rotate_token(
            response=responses.HTTPResponse(
                headers={
                    'X-RateLimit-Remaining': f'{test_github.min_remaining_rate_limit + 1}',
                },
            ),
        )
        assert old_token == test_github.token

        old_token = test_github.token
        test_github._rotate_token(
            response=responses.HTTPResponse(
                headers={
                    'X-RateLimit-Remaining': 'test',
                },
            ),
        )
        assert old_token == test_github.token

    @responses.activate
    def test_post(self, test_github, graphql_payload):
        """ [GitHub] Post """

        responses.add(
            responses.POST, f'https://api.{self.github_host}/graphql', body=json.dumps(graphql_payload),
            headers={'X-RateLimit-Remaining': '2'}, content_type='application/json', status=200,
        )

        old_token = test_github.token
        github_response = test_github.post(
            url=f'https://api.{self.github_host}/graphql', body=json.dumps(graphql_payload),
        )
        assert old_token != test_github.token
        assert 200 == github_response.status_code

    @responses.activate
    def test_post_fail(self, test_github, graphql_payload):
        """ [GitHub] Post """
        test_url = f'https://api.{self.github_host}/graphql'

        responses.add(
            responses.POST, test_url, body=json.dumps(graphql_payload),
            headers={'X-RateLimit-Remaining': '2'}, content_type='application/json', status=401,
        )

        with pytest.raises(requests.exceptions.RequestException, match=r'401 .*'):
            test_github.post(
                url=test_url,
                body=json.dumps(graphql_payload),
            )

    @responses.activate
    def test_get(self, test_github, graphql_payload):
        """ [GitHub] Get """

        responses.add(
            responses.GET, f'https://api.{self.github_host}/graphql', body=json.dumps(graphql_payload),
            headers={'X-RateLimit-Remaining': '200'}, content_type='application/json', status=200,
        )

        test_github._rotate_token()
        old_token = test_github.token
        github_response = test_github.get(
            url=f'https://api.{self.github_host}/graphql',
        )
        assert old_token == test_github.token
        assert 200 == github_response.status_code

    @responses.activate
    def test_no_rate_limit_heading(self, test_github, graphql_payload):
        """ [GitHub] Get """

        responses.add(
            responses.GET, f'https://api.{self.github_host}/graphql', body=json.dumps(graphql_payload),
            content_type='application/json', status=200,
        )

        github_response = test_github.get(
            url=f'https://api.{self.github_host}/graphql',
        )
        assert 200 == github_response.status_code

    @pytest.mark.parametrize(
        'status_code',
        [
            404,
            409,
            500,
            502,
        ],
    )
    @responses.activate
    def test_retry_success(self, test_github, monkeypatch, status_code):
        retry_count = 2
        monkeypatch.setenv('MAX_REQ_TRIES', str(retry_count))

        test_url = f'https://{self.github_host}/api/v3/repos/fake_org/fake_repo/commits/commit_id'

        responses.add(
            responses.GET, test_url,
            headers={'X-RateLimit-Remaining': '200'}, body='this is a test diff', status=status_code,
        )
        responses.add(
            responses.GET, test_url,
            headers={'X-RateLimit-Remaining': '200'}, body='this is a test diff', status=200,
        )

        github_response = test_github.get(
            url=test_url,
        )
        assert 200 == github_response.status_code

    @pytest.mark.parametrize(
        'status_code',
        [
            401,
            403,
            422,  # Client Error: Unprocessable Entity
        ],
    )
    @responses.activate
    def test_retry_give_up_on_fatal(self, test_github, status_code):
        test_url = f'https://{self.github_host}/api/v3/repos/fake_org/fake_repo/commits/commit_id'

        responses.add(
            responses.GET, test_url,
            headers={'X-RateLimit-Remaining': '200'}, body='this is a test diff', status=status_code,
        )

        with pytest.raises(requests.exceptions.RequestException, match=fr'{status_code} .*'):
            test_github.get(
                url=test_url,
            )

    @responses.activate
    def test_retry_give_up_on_max_retries(self, test_github, monkeypatch):
        retry_count = 1
        monkeypatch.setenv('MAX_REQ_TRIES', str(retry_count))

        test_url = f'https://{self.github_host}/api/v3/repos/fake_org/fake_repo/commits/commit_id'

        for i in range(retry_count+1):
            responses.add(
                responses.GET, test_url,
                headers={'X-RateLimit-Remaining': '200'}, body='this is a test diff', status=409,
            )

        responses.add(
            responses.GET, test_url,
            headers={'X-RateLimit-Remaining': '200'}, body='this is a test diff', status=200,
        )

        with pytest.raises(requests.exceptions.RequestException, match=r'409 .*'):
            test_github.get(
                url=test_url,
            )

    @patch('logging.Logger.error')
    def test_error_on_exhausted_token_pool(self, mock_error, test_github):
        test_github._rotate_token(
            response=responses.HTTPResponse(
                headers={
                    'X-RateLimit-Remaining': f'{test_github.min_remaining_rate_limit - 1}',
                },
            ),
        )
        test_github._rotate_token(
            response=responses.HTTPResponse(
                headers={
                    'X-RateLimit-Remaining': f'{test_github.min_remaining_rate_limit - 1}',
                },
            ),
        )
        test_github._rotate_token(
            response=responses.HTTPResponse(
                headers={
                    'X-RateLimit-Remaining': f'{test_github.min_remaining_rate_limit - 1}',
                },
            ),
        )

        mock_error.assert_called()

    @patch('logging.Logger.error')
    def test_no_error_on_unexhausted_token_pool(self, mock_error, test_github):
        test_github._rotate_token(
            response=responses.HTTPResponse(
                headers={
                    'X-RateLimit-Remaining': f'{test_github.min_remaining_rate_limit - 1}',
                },
            ),
        )

        mock_error.assert_not_called()
