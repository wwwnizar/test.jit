import logging
import os
import time

import jwt
from requests.exceptions import HTTPError

from ..github_client.github import GitHub
from ..util.conf import ConfUtil
from .installation_id_request_exception import InstallationIDRequestException


class GitHubApp(object):

    def __init__(
        self, app_id=os.getenv('APP_ID'),
        app_private_key_filename=os.getenv('APP_PRIVATE_KEY_FILENAME'),
        jwt_ttl_minutes=10, jwt_refresh_mins_before_expiry=2,
    ):
        self._app_id = app_id
        if not os.path.isfile(app_private_key_filename):
            raise Exception(f'app_private_key_filename={app_private_key_filename} is not a regular file')
        app_private_key_file = open(app_private_key_filename, 'rb')
        self._app_private_key = app_private_key_file.read()
        self._github_host = ConfUtil.load_github_conf()['host']

        self._jwt_ttl_minutes = jwt_ttl_minutes
        self._jwt_refresh_mins_before_expiry = jwt_refresh_mins_before_expiry

        self.logger = logging.getLogger(__name__)

        # initialize jwt token and github client
        self._github = GitHub()
        self._jwt_expire_time = None
        self._app_github = None
        self._refresh_jwt_token()

    def _refresh_jwt_token(self):
        """ If self._app_github is not initialized or _jwt_expire_time is within
        self._jwt_refresh_mins_before_expiry minutes from expiring,
        refresh the jwt token and initialize the github client with it. """
        current_time = int(time.time())
        # https://developer.github.com/apps/building-github-apps/authenticating-with-github-apps/#authenticating-as-a-github-app
        if self._app_github is None or \
                current_time + (self._jwt_refresh_mins_before_expiry * 60) >= self._jwt_expire_time:
            self._jwt_expire_time = current_time + (self._jwt_ttl_minutes * 60)
            payload = {
                'iat': current_time,
                'exp': self._jwt_expire_time,
                'iss': self._app_id,
            }

            jwt_token = jwt.encode(payload, self._app_private_key, algorithm='RS256')
            self._app_github = GitHub(token_list=[jwt_token])

    def _get_installation_id(self, org_or_repo):
        """ Gets the installation id of the app for the given org, repo, or user.
        Throws InstallationIDRequestException if the app is not installed. """
        # https://developer.github.com/v3/apps/#get-a-user-installation-for-the-authenticated-app
        # https://developer.github.com/v3/apps/#get-a-repository-installation-for-the-authenticated-app
        # https://developer.github.com/v3/apps/#get-an-organization-installation-for-the-authenticated-app
        self._refresh_jwt_token()

        try:
            if '/' in org_or_repo:
                endpoint = f'https://{self._github_host}/api/v3/repos/{org_or_repo}/installation'
            else:
                # check if org_name is a username
                response = self._github.get(f'https://{self._github_host}/api/v3/users/{org_or_repo}').json()
                if response['type'] == 'Organization':
                    endpoint = f'https://{self._github_host}/api/v3/orgs/{org_or_repo}/installation'
                elif response['type'] == 'User':
                    endpoint = f'https://{self._github_host}/api/v3/users/{org_or_repo}/installation'
                else:
                    raise InstallationIDRequestException('Can not determine the user type for %s' % org_or_repo)

            headers = {'accept': 'application/vnd.github.machine-man-preview+json'}
            response = self._app_github.get(
                endpoint,
                headers=headers,
            )
            return response.json()['id']
        except HTTPError as http_err:
            self.logger.error(
                'Installation ID request to GHE API caused an HTTP error: %s' % http_err, exc_info=1,
            )
            raise InstallationIDRequestException
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise InstallationIDRequestException

    def _create_installation_token(self, installation_id):
        """ Creates/returns an installation token which can be used to authenticate with
        the app's permissions on a repo. """
        # https://developer.github.com/v3/apps/#create-a-new-installation-token
        self._refresh_jwt_token()
        try:
            headers = {'accept': 'application/vnd.github.machine-man-preview+json'}
            response = self._app_github.post(
                f'https://{self._github_host}/api/v3/app/installations/{installation_id}/access_tokens',
                headers=headers,
                body={},
            )
            return response.json()['token']
        except HTTPError as http_err:
            self.logger.error(
                'Installation token creation request to GHE API caused an HTTP error: %s' % http_err, exc_info=1,
            )
            raise http_err
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise e

    def get_github_client(self, org_or_repo):
        """ Get a GitHub client object that's authenticated to access an org, repo,
        or user via an app installation token.
        Throws InstallationIDRequestException if the app is not installed on the org,
        repo, or user provided.

        params: org, repo, or user name, string """
        installation_id = self._get_installation_id(org_or_repo)
        installation_token = self._create_installation_token(installation_id)
        return GitHub(token_list=[installation_token], auth_header_type='token')
