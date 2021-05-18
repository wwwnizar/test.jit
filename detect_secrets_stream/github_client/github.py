import itertools
import logging
import os

import backoff
import requests

from ..util.conf import ConfUtil


def fatal_code(e):
    # 422 Client Error: Unprocessable Entity
    return e.response.status_code in (401, 403, 422)


def ghe_max_tries():
    return int(os.getenv('MAX_REQ_TRIES', 3))


class GitHub(object):
    """ Class for calling GHE API using a pool of GitHub API tokens provided in token_list.
    A pool of tokens is necessary because each is rate limited to 5000 requests
    per hour. This class will rotate the token it's using once the remaining rate
    limit falls below min_remaining_rate_limit. It will also raise an error to the
    logger if ALL the tokens become depleted below min_remaining_rate_limit,
    but at least len(token_list) calls must be made using the same GitHub object
    before that can be detected.
    """

    def __init__(
        self,
        token_list=ConfUtil.load_github_conf()['tokens'].split(','),
        min_remaining_rate_limit=100,
        auth_header_type='bearer',
    ):
        self.logger = logging.getLogger(__name__)
        self.__token = None
        self.__tokens = itertools.cycle(token_list)
        self.__min_remaining_rate_limit = min_remaining_rate_limit
        self.__auth_header_type = auth_header_type
        self.__token_pool_size = len(token_list)
        self.__exhausted_token_list = []

    @property
    def min_remaining_rate_limit(self):
        return self.__min_remaining_rate_limit

    @property
    def token(self):
        return self.__token

    @property
    def auth_header_type(self):
        return self.__auth_header_type

    @token.setter
    def token(self, token):
        self.__token = token

    @auth_header_type.setter
    def auth_header_type(self, auth_header_type):
        self.__auth_header_type = auth_header_type

    def _rotate_token(self, response=None):
        if not response:
            self.__token = next(self.__tokens)
            return

        remaining_limit = response.headers.get('X-RateLimit-Remaining')
        self.logger.debug(f'GHE API requests remaining: {remaining_limit}')
        try:
            if remaining_limit and int(remaining_limit) < self.__min_remaining_rate_limit:
                self.__exhausted_token_list.append(self.__token)
                self.__token = next(self.__tokens)
            elif self.__token in self.__exhausted_token_list:
                self.__exhausted_token_list.remove(self.__token)

            if len(self.__exhausted_token_list) == self.__token_pool_size:
                self.logger.error(
                    'Token pool exhausted. Remaining rate limit under ',
                    f'{self.__min_remaining_rate_limit} on all {self.__token_pool_size} tokens.',
                )

        except Exception as e:
            self.logger.error(
                f'Unexpected error while parsing X-RateLimit-Remaining. Error: {e}', exc_info=1,
            )

    def _get_auth_header(self):
        if self.__token is None:
            self._rotate_token()
        return {'Authorization': '%s %s' % (self.__auth_header_type, self.__token)}

    def post(self, url, body, headers={}):
        try:
            response = requests.post(
                url=url,
                headers=dict(headers, **self._get_auth_header()),
                data=body,
                timeout=10,
                stream=True,
                verify=True,
            )

            self._rotate_token(response)

            response.raise_for_status()

            return response
        except Exception as e:
            self.logger.error(
                f'Unexpected error while posting request. Error: {e}', exc_info=1,
            )
            raise e

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.RequestException,
        giveup=fatal_code,
        max_tries=ghe_max_tries,
    )
    def get(self, url, headers={}, params={}):
        try:
            response = requests.get(
                url=url,
                headers=dict(headers, **self._get_auth_header()),
                params=dict(params),
                timeout=10,
                stream=True,
                verify=True,
            )

            self._rotate_token(response)

            response.raise_for_status()

            return response
        except Exception as e:
            self.logger.error(
                f'Unexpected error while getting data. Error {e}', exc_info=1,
            )
            raise e
