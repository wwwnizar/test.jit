import logging

import requests
from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.slack import SlackDetector

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class SlackValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return SlackDetector.secret_type

    def validate(self, secret, other_factors=None) -> bool:
        slack_token = secret

        if type(slack_token) == bytes:
            slack_token = slack_token.decode('UTF-8')

        verify_result = SlackDetector().verify(token=slack_token)

        if verify_result == VerifiedResult.VERIFIED_TRUE:
            return True
        elif verify_result == VerifiedResult.VERIFIED_FALSE:
            return False
        else:
            raise ValidationException('Fail to validate Slack token')

    def resolve_owner(self, secret, other_factors=None):
        '''
        Owner resolution follows priority like below

        User token xoxp

        1. users.info - response['user']['profile']['email']
        2. auth.test  - response['user'] (not an email)
        3. empty string

        Bot token xoxb

        1. auth.test  - response['user'] (not an email)
        2. empty string
        '''
        token = secret

        email = ''
        response = requests.post(
            'https://slack.com/api/auth.test',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-type': 'application/json',
            },
        ).json()
        self.logger.info(f'auth.test response: {response}')

        if not response['ok']:
            return email

        user_id = response['user_id']
        email = response['user']
        response = requests.post(
            f'https://slack.com/api/users.info?user={user_id}',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-type': 'application/json',
            },
        ).json()

        self.logger.info(f'users.info response: {response}')

        # When the token does not have permission to access users.info
        # this method would get response.ok = false
        if not response['ok'] or 'user' not in response:
            self.logger.warning('Fail to get users.info')
        elif 'is_bot' in response['user'] and response['user']['is_bot']:
            # Currently not supporting bot user
            pass
        elif 'email' in response['user']['profile']:
            email = response['user']['profile']['email']

        return email

    def revoke(self, secret, other_factors=None, secret_id=None):
        """ Revokes a Slack token. Returns Boolean representing whether or not
        secret was revoked. Throws RevocationError on exception. Note that this
        function only supports revocation for Slack tokens, not webhooks. """
        if secret.startswith('https://hooks.slack.com/services/'):
            raise RevocationException('Unsupported operation. Cannot revoke a Slack webhook.')
        try:
            response = requests.post(
                'https://slack.com/api/auth.revoke',
                data={
                    'token': secret,
                },
            ).json()
            return response['ok'] is True and response['revoked'] is True
        except Exception as e:
            self.logger.error(
                f'Unexpected error while revoking token. Error {e}', exc_info=1,
            )
            raise RevocationException('Failed to revoke Slack token.')
