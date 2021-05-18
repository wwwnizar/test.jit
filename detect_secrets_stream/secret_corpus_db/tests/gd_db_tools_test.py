import datetime

import psycopg2
import pytest

from detect_secrets_stream.scan_worker.commit import Commit
from detect_secrets_stream.secret_corpus_db.gd_db_tools import add_commit_row
from detect_secrets_stream.secret_corpus_db.gd_db_tools import add_token_row
from detect_secrets_stream.secret_corpus_db.gd_db_tools import generate_report_live_token
from detect_secrets_stream.secret_corpus_db.gd_db_tools import generate_report_recently_remediated
from detect_secrets_stream.secret_corpus_db.gd_db_tools import get_all_tokens
from detect_secrets_stream.secret_corpus_db.gd_db_tools import get_commit_encrypted_columns_all
from detect_secrets_stream.secret_corpus_db.gd_db_tools import get_commit_encrypted_columns_by_id
from detect_secrets_stream.secret_corpus_db.gd_db_tools import get_live_tokens
from detect_secrets_stream.secret_corpus_db.gd_db_tools import get_remediated_tokens
from detect_secrets_stream.secret_corpus_db.gd_db_tools import get_token_id_by_type_hash
from detect_secrets_stream.secret_corpus_db.gd_db_tools import truncate_vmt_report
from detect_secrets_stream.secret_corpus_db.gd_db_tools import update_commit_by_commit_id
from detect_secrets_stream.secret_corpus_db.gd_db_tools import update_commit_encrypted_columns_by_id
from detect_secrets_stream.secret_corpus_db.gd_db_tools import update_location_url_by_hash_and_repo
from detect_secrets_stream.secret_corpus_db.gd_db_tools import update_other_factors_by_token_id
from detect_secrets_stream.secret_corpus_db.gd_db_tools import update_token_hash_by_id
from detect_secrets_stream.secret_corpus_db.gd_db_tools import update_token_uuid_by_id
from detect_secrets_stream.secret_corpus_db.gd_db_tools import vaildate_name
from detect_secrets_stream.secret_corpus_db.gd_db_tools import write_vmt_report
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_commit_by_hash
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_commit_by_id
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_commit_by_token_id
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_commit_count
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_token_by_id
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_token_count
from detect_secrets_stream.secret_corpus_db.tests.conftest import _get_vmt_report_count
from detect_secrets_stream.secret_corpus_db.tests.conftest import _insert_token_data
from detect_secrets_stream.util.conf import ConfUtil


email_domain = 'test.test'


def test_add_token_row_integration(database_with_data):
    old_count = _get_token_count(database_with_data)

    return_id = add_token_row(
        database_with_data, 'token_cred', 'token_type', 'token_comment',
        'other_factors', 'uuid', True, token_hash='hash',
    )
    assert return_id is not None

    new_count = _get_token_count(database_with_data)
    assert new_count == 1 + old_count


def test_get_token_id_by_type_hash_integration(database):
    token_type = 'test type'
    token_hash = 'hash1'

    token_ids = get_token_id_by_type_hash(database, token_type, token_hash)
    assert len(token_ids) == 0

    # insert some data
    _insert_token_data(
        database, 'cred', token_type, 'comment', 'filename', 'linenumber', token_hash,
        'other_factors', 'uuid',
    )

    token_ids = get_token_id_by_type_hash(database, token_type, token_hash)
    assert len(token_ids) == 1

    # test only_live param...
    _insert_token_data(
        database, 'cred', token_type, 'comment', 'filename', 'linenumber', token_hash,
        'other_factors', 'uuid', is_live=False,
    )

    # don't consider is_live=False secrets if only_live=True
    token_ids = get_token_id_by_type_hash(database, token_type, token_hash, only_live=True)
    assert len(token_ids) == 1

    # consider is_live=False secrets if only_live=False (default)
    token_ids = get_token_id_by_type_hash(database, token_type, token_hash)
    assert len(token_ids) == 2


def test_add_commit_row_integration(database):
    old_count = _get_commit_count(database)

    token_id = 1

    commit_id = add_commit_row(
        database, token_id, 'hash', 'repo', 'branch', 'filename_located', 'linenumber_located',
        'author_name', 'author_email', 'pusher_username', 'pusher_email', 'committer_user',
        'committer_email', 'location_url', True, 'uniqueness_hash',
    )

    new_count = _get_commit_count(database)
    assert new_count == 1 + old_count
    assert commit_id is not None
    assert type(commit_id) is int


def test_unique_hash_constraint_integration_with_commit_object(database):
    test_commit = Commit('test-commit-hash', 'test-repo-slug', 'test-branch-name')
    test_commit.token_id = 1
    test_commit.filename = 'test-filename'
    test_commit.linenumber = 1
    test_commit.repo_public = True
    test_commit.author_name = 'test-author-name'
    test_commit.author_email = 'test-author-email'
    test_commit.pusher_username = 'test-pusher-username'
    test_commit.pusher_email = 'test-pusher-email'
    test_commit.committer_name = 'test-committer-name'
    test_commit.committer_email = 'test-committer-email'
    test_commit.location_url = 'test-location-url'
    test_commit.generate_uniqueness_hash()

    add_commit_row(
        database, test_commit.token_id, test_commit.commit_hash, test_commit.repo_slug,
        test_commit.branch_name, test_commit.filename, test_commit.linenumber,
        test_commit.author_name, test_commit.author_email, test_commit.pusher_username,
        test_commit.pusher_email, test_commit.committer_name, test_commit.committer_email,
        test_commit.location_url, test_commit.repo_public, test_commit.uniqueness_hash,
    )

    with pytest.raises(
        psycopg2.errors.UniqueViolation,
        match=r'duplicate key value violates unique constraint "unique_leak_hash"',
    ):
        add_commit_row(
            database, test_commit.token_id, test_commit.commit_hash, test_commit.repo_slug,
            test_commit.branch_name, test_commit.filename, test_commit.linenumber,
            test_commit.author_name, test_commit.author_email, test_commit.pusher_username,
            test_commit.pusher_email, test_commit.committer_name, test_commit.committer_email,
            test_commit.location_url, test_commit.repo_public, test_commit.uniqueness_hash,
        )


def test_unique_hash_constraint_integration(database):
    token_id = 1

    add_commit_row(
        database, token_id, 'hash1', 'repo1', 'branch1', 'filename_located', 'linenumber_located',
        'author_name', 'author_email', 'pusher_username', 'pusher_email', 'committer_user',
        'committer_email', 'location_url', True, 'uniqueness_hash',
    )

    with pytest.raises(
        psycopg2.errors.UniqueViolation,
        match=r'duplicate key value violates unique constraint "unique_leak_hash"',
    ):
        add_commit_row(
            database, token_id, 'hash2', 'repo2', 'branch2', 'filename_located', 'linenumber_located',
            'author_name', 'author_email', 'pusher_username', 'pusher_email', 'committer_user',
            'committer_email', 'location_url', True, 'uniqueness_hash',
        )


@pytest.mark.parametrize(
    'token_id, to_be_token_hash',
    [
        (1, str(datetime.datetime.now())),
        (1, ''),
    ],
)
def test_update_token_hash_by_id_integration(database_with_data, token_id, to_be_token_hash):
    token = _get_token_by_id(database_with_data, token_id)
    _, _, _, _, _, _, old_token_hash, _, _ = token

    update_token_hash_by_id(database_with_data, token_id, to_be_token_hash)

    token = _get_token_by_id(database_with_data, token_id)
    new_token_id, _, _, _, _, _, new_token_hash, _, _ = token

    assert token_id == new_token_id
    assert to_be_token_hash == new_token_hash
    assert old_token_hash != new_token_hash


@pytest.mark.parametrize(
    'token_id',
    [
        None,
        100,  # non existed value
    ],
)
def test_update_token_hash_by_id_not_existed_integration(database_with_data, token_id):
    token = _get_token_by_id(database_with_data, token_id)
    assert token is None

    update_token_hash_by_id(database_with_data, token_id, 'test hash')

    token = _get_token_by_id(database_with_data, token_id)
    assert token is None


@pytest.mark.parametrize(
    'token_id, to_be_token_uuid',
    [
        (1, str(datetime.datetime.now())),
        (1, ''),
    ],
)
def test_update_token_uuid_by_id_integration(database_with_data, token_id, to_be_token_uuid):
    token = _get_token_by_id(database_with_data, token_id)
    _, _, _, _, _, _, _, old_token_uuid, _ = token

    update_token_uuid_by_id(database_with_data, token_id, to_be_token_uuid)

    token = _get_token_by_id(database_with_data, token_id)
    new_token_id, _, _, _, _, _, _, new_token_uuid, _ = token

    assert token_id == new_token_id
    assert to_be_token_uuid == new_token_uuid
    assert old_token_uuid != new_token_uuid


def test_update_token_uuid_by_id_integration_uuid_none(database_with_data):

    with pytest.raises(psycopg2.errors.NotNullViolation):
        update_token_uuid_by_id(database_with_data, 1, None)


@pytest.mark.parametrize(
    'token_id',
    [
        None,
        100,  # non existed value
    ],
)
def test_update_token_uuid_by_id_not_existed_integration(database_with_data, token_id):
    token = _get_token_by_id(database_with_data, token_id)
    assert token is None

    update_token_uuid_by_id(database_with_data, token_id, 'test uuid')

    token = _get_token_by_id(database_with_data, token_id)
    assert token is None


def test_update_commit_by_commit_id(database_with_data):
    commit_id = 1

    commit = _get_commit_by_id(database_with_data, commit_id)
    old_commit_id, old_hash, old_repo, old_branch, old_author_name, old_author_email, old_pusher_username, \
        old_pusher_email, old_committer_name, old_committer_email, old_location_url, old_repo_public, \
        old_uniqueness_hash, old_filename, old_linenumber, old_token_id = commit

    to_be_hash = 'hash2'
    to_be_repo = 'repo2'
    to_be_branch = 'branch2'
    to_be_location_url = 'location2'
    to_be_repo_public = True
    to_be_pusher_username = 'pusher2'
    to_be_pusher_email = f'pusher2@{email_domain}'
    to_be_author_name = 'author2'
    to_be_author_email = f'author2@{email_domain}'
    to_be_committer_name = 'committer2'
    to_be_committer_email = f'committer2@{email_domain}'
    to_be_uniqueness_hash = 'uniqueness_hash_2'
    to_be_filename = 'filename_2'
    to_be_linenumber = '0'
    to_be_token_id = 123

    update_commit_by_commit_id(
        database_with_data, commit_id, to_be_hash, to_be_repo, to_be_branch,
        to_be_location_url, to_be_pusher_username, to_be_pusher_email, to_be_author_name,
        to_be_author_email, to_be_committer_name, to_be_committer_email, to_be_repo_public,
        to_be_uniqueness_hash, to_be_filename, to_be_linenumber, to_be_token_id,
    )

    commit = _get_commit_by_id(database_with_data, commit_id)
    new_commit_id, new_hash, new_repo, new_branch, new_author_name, new_author_email, new_pusher_username, \
        new_pusher_email, new_committer_name, new_committer_email, new_location_url, new_repo_public, \
        new_uniqueness_hash, new_filename, new_linenumber, new_token_id = commit

    assert commit_id == new_commit_id
    assert commit_id == old_commit_id

    assert to_be_hash == new_hash
    assert to_be_repo == new_repo
    assert to_be_branch == new_branch
    assert to_be_location_url == new_location_url
    assert to_be_repo_public == new_repo_public
    assert to_be_pusher_username == new_pusher_username
    assert to_be_pusher_email == new_pusher_email
    assert to_be_author_name == new_author_name
    assert to_be_author_email == new_author_email
    assert to_be_committer_name == new_committer_name
    assert to_be_committer_email == new_committer_email
    assert to_be_uniqueness_hash == new_uniqueness_hash
    assert to_be_filename == new_filename
    assert to_be_linenumber == new_linenumber
    assert to_be_token_id == new_token_id

    assert old_hash != new_hash
    assert old_repo != new_repo
    assert old_branch != new_branch
    assert old_location_url != new_location_url
    assert old_repo_public != new_repo_public
    assert old_pusher_username != new_pusher_username
    assert old_pusher_email != new_pusher_email
    assert old_author_name != new_author_name
    assert old_author_email != new_author_email
    assert old_committer_name != new_committer_name
    assert old_committer_email != new_committer_email
    assert old_uniqueness_hash != new_uniqueness_hash
    assert old_filename != new_filename
    assert old_linenumber != new_linenumber
    assert old_token_id != new_token_id


def test_get_commit_encrypted_columns_by_id(database_with_data):
    commits = get_commit_encrypted_columns_by_id(database_with_data, 1)
    assert len(commits) == 1

    commit = commits[0]
    commit_id, commit_hash, commit_branch, filename, linenumber, location_url = (commit)

    assert commit_id is not None
    assert commit_hash is not None
    assert commit_branch is not None
    assert filename is not None
    assert linenumber is not None
    assert location_url is not None


def test_get_commit_encrypted_columns_all(database_with_data):
    commits = get_commit_encrypted_columns_all(database_with_data)
    assert len(commits) > 0

    for commit in commits:
        commit_id, commit_hash, commit_branch, filename, linenumber, location_url = (commit)

        assert commit_id is not None
        assert commit_hash is not None
        assert commit_branch is not None
        assert filename is not None
        assert linenumber is not None
        assert location_url is not None


def test_get_live_tokens(database):
    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=False,
    )

    tokens = get_live_tokens(database)
    assert len(tokens) == 0

    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=True,
    )

    tokens = get_live_tokens(database)
    assert len(tokens) == 1

    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=None,
    )

    tokens = get_live_tokens(database)
    assert len(tokens) == 2


def test_get_remediated_tokens(database):
    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=True,
    )

    tokens = get_remediated_tokens(database)
    assert len(tokens) == 0

    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=False,
    )

    tokens = get_remediated_tokens(database)
    assert len(tokens) == 1

    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=False,
    )

    tokens = get_remediated_tokens(database)
    assert len(tokens) == 2


def test_get_all_tokens(database):
    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=True,
    )

    tokens = get_all_tokens(database)
    assert len(tokens) == 1

    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=False,
    )

    tokens = get_all_tokens(database)
    assert len(tokens) == 2

    _insert_token_data(
        database, 'cred', 'token_type', 'comment', 'filename', 'linenumber', 'token_hash',
        'other_factors', 'uuid', is_live=False,
    )

    tokens = get_all_tokens(database)
    assert len(tokens) == 3


def test_get_commit_by_token_id(database_with_data):
    token_id = 1
    commit = _get_commit_by_token_id(database_with_data, token_id)
    commit_id, commit_hash, repo_slug, branch_name, \
        location_url, author_name, author_email, pusher_username, \
        pusher_email, committer_name, committer_email, repo_public = (commit)

    assert commit_hash == 'commit_hash'
    assert repo_slug == 'repo_name'
    assert branch_name == 'branch_name'
    assert author_name == 'author'
    assert author_email == f'author@{email_domain}'
    assert pusher_username == 'pusher'
    assert pusher_email == f'pusher@{email_domain}'
    assert committer_name == 'committer'
    assert committer_email == f'committer@{email_domain}'
    assert location_url == 'location_url'
    assert repo_public is False


def test_update_commit_encrypted_columns_by_id(database_with_data):
    commit_id = 1

    commits = get_commit_encrypted_columns_by_id(database_with_data, commit_id)
    assert len(commits) == 1
    commit = commits[0]
    _, commit_hash, commit_branch, filename, linenumber, location_url = (commit)

    new_commit_hash = commit_hash + ' new'
    new_commit_branch = commit_branch + ' new'
    new_filename = filename + ' new'
    new_linenumber = linenumber + ' new'
    new_location_url = location_url + ' new'

    update_commit_encrypted_columns_by_id(
        database_with_data,
        commit_id,
        new_commit_hash,
        new_commit_branch,
        new_filename,
        new_linenumber,
        new_location_url,
    )

    updated_commits = get_commit_encrypted_columns_by_id(database_with_data, commit_id)
    assert len(updated_commits) == 1
    updated_commit = updated_commits[0]
    _, updated_commit_hash, updated_commit_branch, updated_filename, \
        updated_linenumber, updated_location_url = (updated_commit)

    assert new_commit_hash == updated_commit_hash
    assert commit_hash != updated_commit_hash
    assert new_commit_branch == updated_commit_branch
    assert commit_branch != updated_commit_branch
    assert new_filename == updated_filename
    assert filename != updated_filename
    assert new_linenumber == updated_linenumber
    assert linenumber != updated_linenumber
    assert new_location_url == updated_location_url
    assert location_url != updated_location_url


def test_update_location_url_by_hash_and_repo(database_with_data):
    commit_hash = 'commit_hash'
    repo_name = 'repo_name'
    github_host = ConfUtil.load_github_conf()['host']
    to_be_location_url = f'{github_host}/repo_slug/commit/commit_hash'

    commit = _get_commit_by_hash(database_with_data, commit_hash)
    old_commit_hash, old_repo_name, _, _, _, _, _, _, old_location_url, _ = commit

    update_location_url_by_hash_and_repo(database_with_data, commit_hash, repo_name, to_be_location_url)

    commit = _get_commit_by_hash(database_with_data, commit_hash)
    new_commit_hash, new_repo_name, _, _, _, _, _, _, new_location_url, _ = commit

    assert new_commit_hash == old_commit_hash == commit_hash
    assert new_repo_name == old_repo_name == repo_name
    assert to_be_location_url == new_location_url
    assert old_location_url != new_location_url


def test_update_other_factors_by_token_id(database_with_data):
    token_id = 1

    token = _get_token_by_id(database_with_data, token_id)
    _, _, _, _, _, _, _, _, other_factors = token

    new_other_factors = other_factors + ' new'

    update_other_factors_by_token_id(database_with_data, token_id, new_other_factors)

    updated_token = _get_token_by_id(database_with_data, token_id)
    _, _, _, _, _, _, _, _, updated_other_factors = updated_token

    assert updated_other_factors == new_other_factors
    assert updated_other_factors != other_factors


def test_generate_report_live_token(database_with_data):
    results = generate_report_live_token(database_with_data)
    assert results is not None
    assert type(results) is list


def test_generate_report_recently_remediated(database_with_data):
    results = generate_report_recently_remediated(database_with_data)
    assert results is not None
    assert type(results) is list


def test_truncate_vmt_report(database_with_data):
    count = _get_vmt_report_count(database_with_data)
    assert count == 1
    truncate_vmt_report(database_with_data)

    new_count = _get_vmt_report_count(database_with_data)
    assert new_count == 0


def test_write_vmt_report(database_with_data):
    count = _get_vmt_report_count(database_with_data)
    assert count == 1
    write_vmt_report(
        database_with_data, 'vuln_id', 'token_owner_email', 'token_type',
        'vulnerability', 'pusher_email', 'committer_email', 'author_email',
        '2020-02-01 08:45:00 UTC', '2020-02-01 08:45:00 UTC', 'security_focals',
        False, True,
    )

    new_count = _get_vmt_report_count(database_with_data)
    assert new_count == 2


@pytest.mark.parametrize(
    ('name', 'result'),
    [
        (None, False),
        ('', False),
        ('a b', False),
        ('abc;', False),
        (';abc', False),
        (',', False),
        ('abc', True),
    ],
)
def test_validate_name(name, result):
    assert vaildate_name(name) == result
