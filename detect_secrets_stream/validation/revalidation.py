import datetime
import logging

from detect_secrets_stream.secret_corpus_db.db_biz import DbBiz
from detect_secrets_stream.util.log_util import LogUtil
from detect_secrets_stream.validation.validateException import ValidationException


class Revalidator:
    def __init__(self):
        self.db = None
        self.logger = logging.getLogger(__name__)

    def get_db(self):
        if not self.db:
            self.db = DbBiz(self.logger)
        return self.db

    def revalidate_all(self):
        '''
        Revalidate all live tokens.
        '''
        db = self.get_db()

        token_ids = db.get_live_tokens()
        for token_id in token_ids:
            try:
                self.revalidate(token_id)
            except Exception as e:
                self.logger.warning(f'Fail to revalidate token_id={token_id} with error {e}', exc_info=1)

    def revalidate(self, token_id: str):
        '''
        Revalidate a token. The token is located based on incoming token_id.
        The last_test_date, is_live and last_test_success date would be updated.

        Return True if the DB update is successful
        '''
        self.logger.info(f'Revalidate token_id={token_id}')
        db = self.get_db()

        secret = db.get_secret_from_db(token_id)
        if not secret:
            return False

        tz_now = datetime.datetime.now().astimezone(tz=datetime.timezone.utc)
        secret.last_test_date = tz_now
        try:
            validate_result = secret.verify()
            secret.live = validate_result
            secret.last_test_success = validate_result
            self.logger.info(f'Revalidate token_id={token_id} live={validate_result}')

            if validate_result is False:
                secret.remediation_date = tz_now
        except ValidationException as e:
            self.logger.info(f'Revalidate token_id={token_id} exception={e}', exc_info=1)
            secret.last_test_success = None

        if not secret.is_ready_for_revalidated_db_update():
            self.logger.warning(
                f'[data sanity check] Secret token_id={token_id} does not contain expected fields'
                f'from secret.is_ready_for_revalidated_db_update()',
            )
        result = db.write_secret_to_db(secret)
        return result

    def fix_owner(self, token_id: str, replace=False) -> bool:
        '''
        Fix owner for a token. The token is located based on incoming token_id.

        repalce: whether fix owner again if there is existing value
        Return True if the DB update is successful
        '''
        db = self.get_db()

        secret = db.get_secret_from_db(token_id)
        if not secret:
            return False

        if replace or not secret.owner_email:
            secret.lookup_token_owner()
        result = db.write_secret_to_db(secret)
        return result


if __name__ == '__main__':  # pragma: no cover
    LogUtil.set_root_logger_json()

    revalidator = Revalidator()
    revalidator.revalidate_all()
