import datetime
import logging
import os

from ..util.log_util import LogUtil
from detect_secrets_stream.scan_worker.secret import Secret
from detect_secrets_stream.secret_corpus_db.db_biz import DbBiz


class PICleaner:

    def __init__(self):
        self.db = None
        self.logger = logging.getLogger(__name__)
        self.days_since_remediation_to_delete = int(os.getenv('DAYS_SINCE_REMEDIATION_TO_DELETE', 7))

    def get_db(self):
        if not self.db:
            self.db = DbBiz(self.logger)
        return self.db

    def remove_pi_for_all_remediated_tokens(self):
        '''
        Remove
            - owner email
            - secret
            - encrypted secret
            - other factors
            - author name
            - author email
            - pusher username
            - pusher email
            - committer name
            - committer email
            - repo slug
            - location url
        for all tokens that have been remediated for over 7 days
        '''
        db = self.get_db()

        token_ids = db.get_remediated_tokens_from_db()
        for token_id in token_ids:
            try:
                secret = db.get_secret_from_db(token_id)
                if secret.secret != '' or secret.other_factors != '' or \
                        secret.owner_email != '' or secret.encrypted_secret != '':
                    self.remove_pi(secret)
            except Exception as e:
                self.logger.warning(f'Fail to remove pi for token_id={token_id} with error {e}', exc_info=1)

    def remove_pi(self, secret: Secret):
        '''
        Remove PI associated with the secret including PI both in the token and
        token_commit fields of the DB.

        Returns tuple (result: bool, failed_token_ids: [str], failed_commit_ids: [str])
        '''
        if not secret:
            return False
        self.logger.info(f'Remove PI for token_id={secret.id}')
        db = self.get_db()

        tz_now = datetime.datetime.now().astimezone(tz=datetime.timezone.utc)
        result = True
        failed_token_ids = []
        failed_commit_ids = []
        try:
            if secret.live is False:
                time_delta = tz_now - secret.remediation_date
                days_since_remediation = time_delta.total_seconds() / 60 / 60 / 24
                self.logger.info(f'Remove PI token_id={secret.id} time since remediation_date={time_delta}')
                if days_since_remediation >= self.days_since_remediation_to_delete:
                    secret.delete_pi()
                    if not secret.is_pi_cleaned():
                        failed_token_ids.append(secret.id)
                        self.logger.warning(
                            f'[data sanity check] Remove PI for secret id {secret.id} failed to clean',
                        )

                    secret_write_result = db.write_secret_to_db(secret)
                    if not secret_write_result:
                        failed_token_ids.append(secret.id)
                        self.logger.warning(
                            f'[data sanity check] Remove PI for secret id {secret.id} failed to write to db',
                        )
                    commits = db.get_commits_by_token_id_from_db(secret.id)
                    for commit in commits:
                        commit.delete_pi()
                        if not commit.is_pi_cleaned():
                            failed_commit_ids.append(commit.commit_id)
                            self.logger.warning(
                                f'[data sanity check] Remove PI for commit_id {commit.commit_id} failed to clean',
                            )

                        commit_write_result = db.update_commit_in_db(commit)
                        if not commit_write_result:
                            failed_commit_ids.append(commit.commit_id)
                            self.logger.warning(
                                f'[data sanity check] Remove PI for commit_id {commit.commit_id} failed to write to db',
                            )

        except Exception as e:
            self.logger.info(f'Remove PI token_id={secret.id} exception={e}', exc_info=1)

        if failed_token_ids or failed_commit_ids:
            result = False

        return result, failed_token_ids, failed_commit_ids


if __name__ == '__main__':  # pragma: no cover
    LogUtil.set_root_logger_json()

    pi_cleaner = PICleaner()
    pi_cleaner.remove_pi_for_all_remediated_tokens()
