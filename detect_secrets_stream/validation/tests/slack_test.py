from unittest.mock import patch

import pytest
import responses
from detect_secrets.core.constants import VerifiedResult

from detect_secrets_stream.gd_revoker.revocation_exception import RevocationException
from detect_secrets_stream.validation.slack import SlackValidator
from detect_secrets_stream.validation.validateException import ValidationException


class TestSlack:

    @pytest.mark.parametrize(
        'token, result, expected_valid',
        [
            ('test-token', VerifiedResult.VERIFIED_TRUE, True),
            (b'test-token', VerifiedResult.VERIFIED_TRUE, True),
            ('test-token', VerifiedResult.VERIFIED_FALSE, False),
            (b'test-token', VerifiedResult.VERIFIED_FALSE, False),
        ],
    )
    @patch('detect_secrets.plugins.slack.SlackDetector.verify')
    def test_validate_slack_token(self, mock_verify, token, result, expected_valid):
        mock_verify.return_value = result
        validator = SlackValidator()
        valid = validator.validate(token)
        assert valid is expected_valid

    @patch('detect_secrets.plugins.slack.SlackDetector.verify')
    def test_validate_ibm_cloud_iam_key_unverifiable(self, mock_verify):
        mock_verify.return_value = VerifiedResult.UNVERIFIED
        validator = SlackValidator()
        with pytest.raises(ValidationException):
            validator.validate('test-token')

    @responses.activate
    def test_resolve_owner_user_info(self):
        slack_validator = SlackValidator()
        user_id = '123456'
        auth_test_user = 'auth_test_user'
        user_info_email = 'email'
        responses.add(
            responses.POST, 'https://slack.com/api/auth.test',
            json={'ok': True, 'user_id': user_id, 'user': auth_test_user},
        )
        responses.add(
            responses.POST, f'https://slack.com/api/users.info?user={user_id}',
            json={
                'ok': True, 'user': {
                    'is_bot': False,
                    'profile': {
                        'email': user_info_email,
                    },
                },
            },
        )
        owner = slack_validator.resolve_owner('')
        assert owner == user_info_email

    @responses.activate
    def test_resolve_owner_invalid_token(self):
        slack_validator = SlackValidator()
        responses.add(
            responses.POST, 'https://slack.com/api/auth.test',
            json={'ok': False},
        )
        owner = slack_validator.resolve_owner('')
        assert owner == ''

    @responses.activate
    def test_resolve_owner_bot(self):
        slack_validator = SlackValidator()
        user_id = '123456'
        auth_test_user = 'auth_test_user'
        user_info_email = 'email'
        responses.add(
            responses.POST, 'https://slack.com/api/auth.test',
            json={'ok': True, 'user_id': user_id, 'user': auth_test_user},
        )
        responses.add(
            responses.POST, f'https://slack.com/api/users.info?user={user_id}',
            json={
                'ok': True, 'user': {
                    'is_bot': True,
                    'profile': {
                        'email': user_info_email,
                    },
                },
            },
        )
        owner = slack_validator.resolve_owner('')
        assert owner == auth_test_user

    @responses.activate
    def test_resolve_owner_auth_test(self):
        slack_validator = SlackValidator()
        user_id = '123456'
        auth_test_user = 'auth_test_user'
        responses.add(
            responses.POST, 'https://slack.com/api/auth.test',
            json={'ok': True, 'user_id': user_id, 'user': auth_test_user},
        )
        responses.add(
            responses.POST, f'https://slack.com/api/users.info?user={user_id}',
            json={
                'ok': True, 'user': {
                    'is_bot': False,
                    'profile': {
                    },
                },
            },
        )
        owner = slack_validator.resolve_owner('')
        assert owner == auth_test_user

    @responses.activate
    def test_resolve_owner_no_perm_to_get_users_info(self):
        slack_validator = SlackValidator()
        user_id = '123456'
        auth_test_user = 'auth_test_user'
        responses.add(
            responses.POST, 'https://slack.com/api/auth.test',
            json={'ok': True, 'user_id': user_id, 'user': auth_test_user},
        )
        responses.add(
            responses.POST, f'https://slack.com/api/users.info?user={user_id}',
            json={'ok': False},
        )
        owner = slack_validator.resolve_owner('')
        assert owner == auth_test_user

    @responses.activate
    def test_revoke_slack_token(self):
        responses.add(
            responses.POST,
            'https://slack.com/api/auth.revoke',
            status=200,
            json={'ok': True, 'revoked': True},
        )
        slack_validator = SlackValidator()
        result = slack_validator.revoke('test-secret')
        assert result is True

    @responses.activate
    def test_revoke_slack_token_revoked_false(self):
        responses.add(
            responses.POST,
            'https://slack.com/api/auth.revoke',
            status=200,
            json={'ok': True, 'revoked': False},
        )
        slack_validator = SlackValidator()
        result = slack_validator.revoke('test-secret')
        assert result is False

    @responses.activate
    def test_revoke_slack_token_ok_false(self):
        responses.add(
            responses.POST,
            'https://slack.com/api/auth.revoke',
            status=200,
            json={'ok': False, 'error': 'oops'},
        )
        slack_validator = SlackValidator()
        result = slack_validator.revoke('test-secret')
        assert result is False

    @responses.activate
    def test_revoke_slack_token_server_error(self):
        responses.add(
            responses.POST,
            'https://slack.com/api/auth.revoke',
            status=500,
        )
        slack_validator = SlackValidator()
        with pytest.raises(RevocationException):
            slack_validator.revoke('test-secret')

    @responses.activate
    def test_revoke_unexpected_payload(self):
        responses.add(
            responses.POST,
            'https://slack.com/api/auth.revoke',
            status=200,
            json={'not-the-expected-field': True},
        )
        slack_validator = SlackValidator()
        with pytest.raises(RevocationException):
            slack_validator.revoke('test-secret')

    @responses.activate
    def test_revoke_webhook(self):
        slack_validator = SlackValidator()
        with pytest.raises(
            RevocationException,
            match=r'Unsupported operation. Cannot revoke a Slack webhook.',
        ):
            slack_validator.revoke('https://hooks.slack.com/services/')
