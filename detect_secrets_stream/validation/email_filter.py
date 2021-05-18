import re

from detect_secrets_stream.util.conf import ConfUtil


class EmailFilter:

    def __init__(self):
        self.internal_email_regex = ConfUtil.load_email_conf()['internal_email_regex']

    def filter_external_emails(self, owner):
        '''
        Filter external emails

        Checks if a given string matches the internal email regex, defined in the email.conf.
        The internal email domain can be set by editing the contents of last set of parenthesis in the string.
        The internal email prefix is also configurable.
        All emails which fail to match this regex will be filtered out, i.e. an empty string will be returned.
        If the string is not an email, it will not be filtered out.
        '''
        if owner is None:
            return owner
        email_regex = re.compile(r'[A-Z0-9._%+\-]+@[A-Z0-9.-]+\.[A-Z]{2,}', re.IGNORECASE)
        internal_email_regex = re.compile(rf'{self.internal_email_regex}', re.IGNORECASE)
        if re.match(internal_email_regex, owner):
            return owner
        elif re.match(email_regex, owner):
            return ''
        else:
            return owner
