import csv
import datetime
import os

from ..secret_corpus_db.db_biz import DbBiz
from ..secret_corpus_db.gd_db_tools import connect_db
from ..secret_corpus_db.gd_db_tools import generate_report_live_token
from ..secret_corpus_db.gd_db_tools import generate_report_recently_remediated
from ..secret_corpus_db.gd_db_tools import write_vmt_report
from ..security.security import Decryptor
from ..security.security import DeterministicCryptor
from .org_set_controller import OrgSetController
from detect_secrets_stream.validation.ibm_cloud_iam import IBMCloudIAMValidator


class GdReportGenerator(object):
    """ Generates reports of leaked secrets for VMT """

    def __init__(
        self, include_security_focals=os.getenv('FF_INCLUDE_SECURITY_FOCALS', False) == 'true',
        include_repo_visibility=os.getenv('FF_INCLUDE_REPO_VISIBILITY', False) == 'true',
    ):
        self.fieldnames = [
            'Vuln Id',
            'Business Unit',
            'Token Owner Email',
            'Token type',
            'Vulnerability',
            'Action Required',
            'Pusher email',
            'Committer email',
            'Author email',
            'Date Last Tested',
            'Date Remediated',
        ]

        self.include_security_focals = include_security_focals
        if self.include_security_focals:
            self.fieldnames.append('Security Focals')

        self.include_repo_visibility = include_repo_visibility
        if self.include_repo_visibility:
            self.fieldnames.append('Repo Public')
            self.fieldnames.append('Repo Private')

        self.conn = connect_db()
        self.db = DbBiz()
        self.org_set_controller = OrgSetController()

    def get_dedupped_report(self, include_private_repo_tokens):
        report_live_token = generate_report_live_token(self.conn)
        report_recently_remediated = generate_report_recently_remediated(self.conn)
        report = report_live_token + report_recently_remediated
        keys = [
            'token_id',
            'token_uuid',
            'raw_secret_enc',
            'owner_email',
            'location_url_enc',
            'repo',
            'filename_located_enc',
            'linenumber_located_enc',
            'commit_hash_enc',
            'first_identified',
            'other_factors_enc',
            'token_type',
            'pusher_email',
            'committer_email',
            'author_email',
            'last_test_date',
            'remediation_date',
            'is_live',
            'repo_public',
            'repo_private',
        ]
        dedupped_report = {}
        for token in report:

            token_dict = {}
            for i in range(len(keys)):
                token_dict[keys[i]] = token[i]

            if not token_dict['repo_public'] and not include_private_repo_tokens:
                continue

            uuid = token_dict['token_uuid']
            if uuid in dedupped_report:
                dedupped_report[uuid]['commit_count'] += 1
                if token_dict['repo_public'] is True:
                    # found public repo commit for already processed private repo token
                    dedupped_report[uuid]['repo_public'] = True
                elif token_dict['repo_public'] is False:
                    # found private repo commit for already processed public repo token
                    dedupped_report[uuid]['repo_private'] = True
            else:
                dedupped_report[uuid] = token_dict
                dedupped_report[uuid]['commit_count'] = 1

        return dedupped_report

    def create_row(self, token_uuid, token_dict, org_set_filter=None, include_private_repo_tokens=True):
        # set local variables based on token dict (i.e. key = 'value')
        token_id = token_dict['token_id']
        token_uuid = token_dict['token_uuid']
        owner_email = token_dict['owner_email']
        location_url_enc = token_dict['location_url_enc']
        repo = token_dict['repo']
        filename_located_enc = token_dict['filename_located_enc']
        linenumber_located_enc = token_dict['linenumber_located_enc']
        commit_hash_enc = token_dict['commit_hash_enc']
        first_identified = token_dict['first_identified']
        token_type = token_dict['token_type']
        pusher_email = token_dict['pusher_email']
        committer_email = token_dict['committer_email']
        author_email = token_dict['author_email']
        last_test_date = token_dict['last_test_date']
        remediation_date = token_dict['remediation_date']
        is_live = token_dict['is_live']
        repo_public = token_dict['repo_public']
        repo_private = token_dict['repo_private']
        commit_count = token_dict['commit_count']

        if org_set_filter:
            org_set_names = self.org_set_controller.get_org_set_names_for_repo(repo)
            if org_set_filter not in org_set_names:
                return None

        # decrypt fields
        try:
            # raw_secret = self.decode_hex(raw_secret_enc)
            location_url = self.decode_hex(location_url_enc)
            commit_hash = self.decode_hex(commit_hash_enc)
            filename_located = self.decode_hex(filename_located_enc)
            linenumber_located = self.decode_hex(linenumber_located_enc)
        except Exception as e:
            print(f'Fail to decrypt for token={token_uuid}')
            print(e)
            return None

        last_5 = ''
        other_factors = None
        try:
            if is_live:
                secret = self.db.get_secret_from_db(token_id)
                last_5 = secret.secret[-5:]
                other_factors = secret.other_factors
        except Exception:
            print(f'Fail to get last 5 characters for token={token_uuid}')

        security_focal = ''
        try:
            security_focal_emails = self.org_set_controller.get_security_focal_emails_for_repo(repo)
            security_focal = ','.join(security_focal_emails)
        except Exception:
            print(f'Exception while attempting to retrieve org set information for repo={repo}')

        vulnerability = f"""Last 5 characters of token: {last_5}

Token Owner Email: {owner_email}
HTML file URL: {location_url}
Repo: {repo}
Filename: {filename_located}
Line found: {linenumber_located}
Commit Hash: {commit_hash}
Date found: {self.to_tz_str(first_identified)}
Number of commits discovered in: {commit_count}"""

        if is_live and token_type == 'IBM Cloud IAM Key':
            validator = IBMCloudIAMValidator()
            service_id_uuid, service_id_name = validator.get_service_id_uuid_and_name(secret.secret)
            if service_id_uuid:
                vulnerability = vulnerability + f"""
IBM Cloud IAM Service ID UUID: {service_id_uuid}"""
            if service_id_name:
                vulnerability = vulnerability + f"""
IBM Cloud IAM Service ID Name: {service_id_name}"""

            meta_select = [
                'id',
                'crn',
                'created_at',
                'name',
                'description',
                'iam_id',
                'account_id',
            ]

            service_id_apikey_meta = validator.get_service_id_apikey_meta(secret.secret)

            if service_id_apikey_meta:
                selected_meta = {}
                for ms in meta_select:
                    if ms in service_id_apikey_meta:
                        selected_meta[ms] = service_id_apikey_meta[ms]
                vulnerability = vulnerability + f"""
IBM Cloud IAM KEY Service ID metadata: {selected_meta}"""

        if is_live and token_type == 'Slack Token':
            if secret.secret.startswith('https://hooks.slack.com/services/'):
                token_type = 'Slack Webhook'
            else:
                token_type = 'Slack Token'

        if other_factors:
            vulnerability = vulnerability + f"""
Notes: other factors {other_factors}"""

        row = {
            'Vuln Id': token_uuid,
            'Business Unit': '',
            'Token Owner Email': owner_email,
            'Token type': token_type,
            'Vulnerability': vulnerability,
            'Action Required': '',
            'Pusher email': pusher_email,
            'Committer email': committer_email,
            'Author email': author_email,
            'Date Last Tested': self.to_tz_str(last_test_date),
            'Date Remediated': self.to_tz_str(remediation_date),
        }
        if self.include_security_focals:
            row['Security Focals'] = security_focal
        if self.include_repo_visibility:
            row['Repo Public'] = repo_public
            row['Repo Private'] = repo_private

        return row

    def generate_csv_from_db(self, filename, org_set_filter=None, include_private_repo_tokens=True):
        """
        Generate CSV from database
        """
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
            writer.writeheader()

            dedupped_report = self.get_dedupped_report(include_private_repo_tokens)

            for token_uuid, token_dict in dedupped_report.items():
                csv_row = self.create_row(token_uuid, token_dict, org_set_filter, include_private_repo_tokens)
                if csv_row:
                    writer.writerow(csv_row)

    def generate_vmt_report_in_db(self, include_private_repo_tokens=True):
        """
        Generate VMT report and write it to vmt_report table of database
        """
        dedupped_report = self.get_dedupped_report(include_private_repo_tokens)

        for token_uuid, token_dict in dedupped_report.items():
            row = self.create_row(
                token_uuid,
                token_dict,
                include_private_repo_tokens=include_private_repo_tokens,
                org_set_filter=None,
            )
            if row:
                vuln_id = row['Vuln Id']
                token_owner_email = row['Token Owner Email']
                token_type = row['Token type']
                vulnerability = row['Vulnerability']
                pusher_email = row['Pusher email']
                committer_email = row['Committer email']
                author_email = row['Author email']
                date_last_tested = row['Date Last Tested']
                if date_last_tested == '':
                    date_last_tested = None
                date_remediated = row['Date Remediated']
                if date_remediated == '':
                    date_remediated = None
                security_focals = None
                if self.include_security_focals:
                    security_focals = row['Security Focals']
                repo_public = None
                repo_private = None
                if self.include_repo_visibility:
                    repo_public = row['Repo Public']
                    repo_private = row['Repo Private']
                write_vmt_report(
                    self.conn,
                    vuln_id,
                    token_owner_email,
                    token_type,
                    vulnerability,
                    pusher_email,
                    committer_email,
                    author_email,
                    date_last_tested,
                    date_remediated,
                    security_focals,
                    repo_public,
                    repo_private,
                )

    @staticmethod
    def to_tz_str(timestamp, tz=datetime.timezone.utc):
        return_str = ''
        if type(timestamp) is datetime.datetime:
            return_str = timestamp.astimezone(tz).isoformat(timespec='seconds')
        return return_str

    @staticmethod
    def decode_hex(text: str) -> str:
        if not text:
            return None

        decryptor = Decryptor()
        determ_decryptor = DeterministicCryptor()

        decrypted_text = text
        if text.startswith('\\x'):
            try:
                decrypted_text = decryptor.decrypt(bytes.fromhex(text[2:]))
            except Exception:
                try:
                    decrypted_text = determ_decryptor.decrypt(bytes.fromhex(text[2:]))
                except Exception as e:
                    raise e

        return decrypted_text
