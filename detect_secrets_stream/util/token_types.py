import logging
import sys

from ..github_client.github import GitHub
from ..util.conf import ConfUtil


class TokenTypes(object):

    def __init__(self):
        self.github_host = ConfUtil.load_github_conf()['host']
        self.api_endpoint = f'https://{self.github_host}/api/v3'
        self.github = GitHub()
        self.logger = logging.getLogger(__name__)
        self.add_token_keyword_common_suffix = False
        self.generate_token_list()

    def generate_token_list(self):
        """
        generic_keyword: search keyword indicates how frequently one tool is used by IBMer
        token_keyword: search keyword indicates a token of the tool presents
        """
        if self.add_token_keyword_common_suffix:
            self.logger.debug('Already added common suffix for token keywords')
            return

        self.common_suffix = (
            '_token', '_key', '_apikey',
            '_pass', '_password', '_pwd',
        )

        self.token_list = [


            {
                'type': 'slack',
                'short_name': 'slack',
                'generic_keyword': ['slack'],
                'token_keyword': ['xoxa', 'xoxp', 'xoxb'],
            },
            {
                'type': 'softlayer',
                'short_name': 'sl',
                'generic_keyword': ['softlayer'],
                'token_keyword': [],
            },
            {
                'type': 'google',
                'short_name': 'google',
                'generic_keyword': ['"google.com"'],
                'token_keyword': ['AIza'],
            },
            {
                'type': 'ghe',
                'short_name': ['ghe', 'github'],
                'generic_keyword': [f'{self.github_host}'],
                'token_keyword': [],
            },
            {
                'type': 'box',
                'short_name': 'box',
                'generic_keyword': ['"ibm.box.com"'],
                'token_keyword': [],
            },
            {
                'type': 'artifactory',
                'short_name': ['artifactory', 'art'],
                'generic_keyword': ['artifactory'],
                'token_keyword': [],
            },
            {
                'type': 'pagerduty',
                'short_name': ['pd', 'pagerduty'],
                'generic_keyword': ['pagerduty'],
                'token_keyword': [],
            },
            {
                'type': 'travis',
                'short_name': 'travis',
                'generic_keyword': ['travis'],
                'token_keyword': [],
            },
            {
                'type': 'New Relic',
                'short_name': 'newrelic',
                'generic_keyword': ['newrelic'],
                'token_keyword': [],
            },
            {
                'type': 'IBM Cloud IAM Key',
                'short_name': 'ibm_cloud',
                'generic_keyword': ['"iam.cloud.ibm.com"'],
                'token_keyword': ['"iam.cloud.ibm.com" AND "api_key"'],
            },
            {
                'type': 'IBM Cloud IAM Token',
                'short_name': 'ibm_cloud',
                'generic_keyword': ['"iam.cloud.ibm.com"'],
                'token_keyword': ['"iam.cloud.ibm.com" AND "access_token"'],
            },
            {
                'type': 'IBM Cloud Databases',
                'short_name': ['icd', 'cdb'],
                'generic_keyword': ['"databases.appdomain.cloud"'],
                'token_keyword': [
                    '"PGPASSWORD" AND "databases.appdomain.cloud"', '"mongodb" AND "databases.appdomain.cloud"',
                    '"redis" AND "databases.appdomain.cloud"', '"postgres" AND "databases.appdomain.cloud"',
                    '"https" AND "databases.appdomain.cloud"', '"rabbitmq" AND "databases.appdomain.cloud"',
                    '"etcd" AND "databases.appdomain.cloud"',
                ],
            },
            {
                'type': 'DB2 / dashdb',
                'short_name': ['db2'],
                'generic_keyword': ['dashdb'],
                'token_keyword': ['"bluadmin" AND "db2"'],
            },
            {
                'type': 'IBM Cloud object storage',
                'short_name': 'cos',
                'generic_keyword': ['"cloud-object-storage"'],
                'token_keyword': ['cos_hmac_keys'],
            },
            {
                'type': 'Cloudant',
                'short_name': 'cloudant',
                'generic_keyword': ['cloudant'],
                'token_keyword': [],
            },
            {
                'type': 'Compose DB token',
                'short_name': 'compose',
                'generic_keyword': ['dblayer'],
                'token_keyword': [],
            },
            {
                'type': 'Compose API token',
                'short_name': 'compose',
                'generic_keyword': ['"compose.com"'],
                'token_keyword': [],
            },
            {
                'type': 'Cloud Foundry Token',
                'short_name': 'cf',
                'generic_keyword': ['cloud foundry'],
                'token_keyword': [],
            },
            {
                'type': 'AWS',
                'short_name': 'aws',
                'generic_keyword': ['amazonaws'],
                'token_keyword': ['AKIA'],
            },
            {
                'type': 'SendGrid',
                'short_name': ['sg', 'sendgrid'],
                'generic_keyword': ['sendgrid'],
                'token_keyword': ['"sendgrid sg"'],
            },
            {
                'type': 'Twitter',
                'short_name': 'twitter',
                'generic_keyword': ['twitter'],
                'token_keyword': [],
            },
            {
                'type': 'Facebook',
                'short_name': ['facebook', 'fb'],
                'generic_keyword': ['facebook'],
                'token_keyword': ['EAACEdEose0cBA'],
            },
            {
                'type': 'Stripe',
                'short_name': 'stripe',
                'generic_keyword': ['stripe.com'],
                'token_keyword': ['sk_live', 'rk_live'],
            },
            {
                'type': 'Square',
                'short_name': 'square',
                'generic_keyword': ['square.com'],
                'token_keyword': ['sq0atp', 'sq0csp'],
            },
            {
                'type': 'Paypal',
                'short_name': 'paypal',
                'generic_keyword': ['paypal'],
                'token_keyword': [],
            },
            {
                'type': 'Amazon MWS',
                'short_name': 'amazon_mws',
                'generic_keyword': ['"amzn.mws"'],
                'token_keyword': ['"amzn.mws"'],
            },
            {
                'type': 'Twilio',
                'short_name': 'twilio',
                'generic_keyword': ['twilio'],
                'token_keyword': [],
            },
            {
                'type': 'MailGun',
                'short_name': 'mailgun',
                'generic_keyword': ['mailgun'],
                'token_keyword': [],
            },
            {
                'type': 'MailChimp',
                'short_name': 'mailchimp',
                'generic_keyword': ['mailchimp'],
                'token_keyword': [],
            },
            {
                'type': 'Linkedin',
                'short_name': 'linkedin',
                'generic_keyword': ['linkedin'],
                'token_keyword': [],
            },
        ]

        for token in self.token_list:
            token_keyword_list = token['token_keyword']
            for suffix in self.common_suffix:

                short_name_list = []
                if type(token['short_name']) is str:
                    short_name_list.append(token['short_name'])
                elif type(token['short_name']) is list:
                    short_name_list = token['short_name']

                for short_name in short_name_list:
                    token_keyword_list.append(short_name + suffix)
            token['token_keyword'] = token_keyword_list

        self.add_token_keyword_common_suffix = True

    def search_for_count(self, keyword):
        count = 0

        headers = {
            'Accept': 'application/json',
        }
        params = {'q': keyword}
        try:
            response = self.github.get(
                url=f'{self.api_endpoint}/search/code', headers=headers, params=params,
            )

            response.raise_for_status()

            json_payload = response.json()
            count = json_payload['total_count']
        except Exception as e:
            self.logger.error(e, exc_info=1)

        return count

    def get_token_by_type(self, token_type='all'):
        if token_type == 'all':
            return self.token_list
        else:
            return [token for token in self.token_list if token['type'].lower() == token_type.lower()]

    def analyze(self, token_type=None):
        to_be_analyze_token_list = self.get_token_by_type(token_type)

        for token in to_be_analyze_token_list:
            generic_keyword_count = 0
            for generic_keyword in token['generic_keyword']:
                count = self.search_for_count(generic_keyword)
                generic_keyword_count = generic_keyword_count + count
                self.logger.info(
                    f"type='{token['type']}' keyword='{generic_keyword}' count={count}",
                )

            token_keyword_count = 0
            for token_keyword in token['token_keyword']:
                count = self.search_for_count(token_keyword)
                token_keyword_count = token_keyword_count + count
                self.logger.info(
                    f"type={token['type']} keyword='{token_keyword}' count={count}",
                )

            self.logger.info(
                f"""type='{token['type']}' generic_keyword_count={generic_keyword_count}
                token_keyword_count={token_keyword_count}""",
            )

    def usage(self):
        self.logger.info(
            """Usage: env GHE_TOKEN=<personal_access_token>
            python -m detect_secrets_stream.util.token_types <token_type>|'all'""",
        )


if __name__ == '__main__':
    token_types = TokenTypes()
    token_type = None

    if len(sys.argv) < 2 or len(sys.argv) > 2:
        token_types.usage()
        sys.exit(1)
    else:
        token_type = sys.argv[1]
    count = token_types.analyze(token_type)
