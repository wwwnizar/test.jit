import logging

import requests
from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.artifactory import ArtifactoryDetector

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.secret_corpus_db.db_biz import DbBiz
from detect_secrets_stream.util.conf import ConfUtil
from detect_secrets_stream.validation.base import BaseValidator
from detect_secrets_stream.validation.validateException import ValidationException


class ArtifactoryValidator(BaseValidator):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def secret_type_name():
        return ArtifactoryDetector.secret_type

    def validate(self, secret, other_factors=None):
        try:
            result = ArtifactoryDetector().verify(secret)
            if result == VerifiedResult.VERIFIED_TRUE:
                return True
            elif result == VerifiedResult.VERIFIED_FALSE:
                return False
            else:
                raise ValidationException(
                    'Failed to validate Artifactory token. '
                    '{result} is neither VERIFIED_TRUE or VERIFIED_FALSE.',
                )
        except Exception as e:
            self.logger.error(e, exc_info=1)
            raise ValidationException(
                'Failed to validate Artifactory token.',
            )

    def resolve_owner(self, secret, other_factors=None):
        '''
        Owner resolution by calling npm auth endpoint. It follows priority
        below

        1. email from npm auth response
        2. empty string
        '''
        url = ConfUtil.load_revoker_urls_conf()['artifactory-owner-resolution']

        try:
            response = requests.get(
                url=url,
                headers={'X-JFrog-Art-Api': secret},
                timeout=10,
                verify=True,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.logger.error(
                f'Unexpected error while retrieving owner. Error {e}', exc_info=1,
            )
            raise ValidationException('Failed to resolve Artifactory token owner.')

        # Example output looks like below
        #
        # _auth = some_secret
        # always-auth = true
        # email = someone@mail_server.domain
        for line in response.text.split('\n'):
            tokens = line.split(' ')
            if len(tokens) < 3:
                continue
            if tokens[0] == 'email':
                return tokens[2]

        return ''

    def revoke(self, secret, other_factors=None, secret_id=None):
        """ Revokes an Artifactory secret. Returns Boolean representing whether or not
        secret was revoked. Throws RevocationError on exception. """
        try:
            # resolve where secret was leaked
            locations_string = 'Found in GitHub by Detect Secrets Stream'
            if secret_id:
                locations_list = []
                commits = DbBiz().get_commits_by_token_id_from_db(secret_id)
                for commit in commits:
                    locations_list.append(commit.location_url)
                locations_string = ','.join(locations_list)

            revocation_endpoint = ConfUtil.load_revoker_urls_conf()['artifactory-revocation']
            headers = {'accept': 'application/json'}
            response = requests.post(
                url=revocation_endpoint,
                data={'key': secret, 'foundAt': locations_string},
                headers=headers,
            )
            response.raise_for_status()
            return response.json()['revoked'] is True
        except requests.exceptions.RequestException as e:
            self.logger.error(
                f'Unexpected request exception while revoking token. Error {e}', exc_info=1,
            )
            raise RevocationException('Failed to revoke Artifactory token.')
        except Exception as e:
            self.logger.error(
                f'Unexpected error while revoking token. Error {e}', exc_info=1,
            )
            raise RevocationException('Failed to revoke Artifactory token.')
