import pytest

from detect_secrets_stream.validation.email_filter import EmailFilter


class TestEmailFilter:

    email_domain = 'test.test'

    def test_filter_external_emails(self):

        owner = EmailFilter().filter_external_emails('someone@gmail.com')
        assert owner == ''

    @pytest.mark.parametrize(
        ('email'),
        [
            f'someone@{email_domain}',
            f'someone@nomail.relay.{email_domain}',
            f'some-one@nomail.relay.{email_domain}',
            f'SOMEONE@nomail.relay.{email_domain}',
        ],
    )
    def test_filter_external_emails_valid_internal(self, email):

        owner = EmailFilter().filter_external_emails(email)
        assert owner == email

    def test_filter_external_emails_not_an_email(self):

        owner = EmailFilter().filter_external_emails('notanemail123')
        assert owner == 'notanemail123'
