import psycopg2
import pytest

from detect_secrets_stream.secret_corpus_db.gd_db_tools import create_tables
from detect_secrets_stream.secret_corpus_db.gd_db_tools import table_def


email_domain = 'test.test'


def _get_table_count(conn, table):
    with conn.cursor() as cur:
        sql = f"""select count(*) from {table};"""
        cur.execute(sql)
        count = cur.fetchone()[0]
        return count


def _get_token_count(conn):
    return _get_table_count(conn, 'token')


def _get_commit_count(conn):
    return _get_table_count(conn, 'token_commit')


def _get_vmt_report_count(conn):
    return _get_table_count(conn, 'vmt_report')


def _recreate_tables(conn):
    with conn.cursor() as cur:
        for (table_name, _) in table_def:
            cur.execute('DROP TABLE IF EXISTS "{}";'.format(table_name))
    create_tables(conn)


def _get_token_by_id(conn, token_id):
    with conn.cursor() as cur:
        sql = '''select token_id, token_cred, token_type,
        token_comment, filename_located, linenumber_located, token_hash, uuid,
        other_factors from token where token_id = %s'''
        cur.execute(sql, (token_id,))
        result = cur.fetchone()
        return result


def _get_commit_by_hash(conn, commit_hash):
    with conn.cursor() as cur:
        sql = '''select hash, repo, author_name, author_email, pusher_username,
        pusher_email, committer_name, committer_email, location_url, repo_public from token_commit
        where hash = %s'''
        cur.execute(sql, (commit_hash,))
        result = cur.fetchone()
        return result


def _get_commit_by_id(conn, commit_id):
    with conn.cursor() as cur:
        sql = '''select commit_id, hash, repo, branch, author_name, author_email, pusher_username,
        pusher_email, committer_name, committer_email, location_url, repo_public,
        uniqueness_hash, filename_located, linenumber_located, token_id from token_commit where commit_id = %s'''
        cur.execute(sql, (commit_id,))
        result = cur.fetchone()
        return result


def _get_commit_by_token_id(conn, token_id):
    with conn.cursor() as cur:
        sql = '''select commit_id, hash, repo, branch, location_url, author_name, author_email, pusher_username,
        pusher_email, committer_name, committer_email, repo_public from token_commit
        where token_id = %s'''
        cur.execute(sql, (token_id,))
        result = cur.fetchone()
        return result


def _insert_token_data(
    conn, token_cred, token_type, token_comment, filename_located,
    linenumber_located, token_hash, other_factors, uuid, is_live=True,
):

    sql = """INSERT INTO token (token_cred, token_type, token_comment, filename_located,
                                linenumber_located, token_hash, other_factors, uuid, is_live)
             VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s);"""

    with conn.cursor() as cur:
        cur.execute(
            sql, (
                token_cred, token_type, token_comment, filename_located,
                linenumber_located, token_hash, other_factors, uuid, is_live,
            ),
        )


def _insert_commit_data(
    conn,
    token_id,
    hash,
    repo,
    branch,
    filename,
    linenumber,
    author_name,
    author_email,
    pusher_username,
    pusher_email,
    committer_name,
    committer_email,
    location_url,
    repo_public,
    uniqueness_hash,
):
    sql = """INSERT INTO token_commit (
        token_id,
        hash,
        repo,
        branch,
        filename_located,
        linenumber_located,
        author_name,
        author_email,
        pusher_username,
        pusher_email,
        committer_name,
        committer_email,
        location_url,
        repo_public,
        uniqueness_hash
        )
        VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"""

    with conn.cursor() as cur:
        cur.execute(
            sql, (
                token_id,
                hash,
                repo,
                branch,
                filename,
                linenumber,
                author_name,
                author_email,
                pusher_username,
                pusher_email,
                committer_name,
                committer_email,
                location_url,
                repo_public,
                uniqueness_hash,
            ),
        )


def _insert_vmt_report_data(
    conn,
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
):
    sql = """INSERT INTO vmt_report(
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
        repo_private
    ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"""

    with conn.cursor() as cur:
        cur.execute(
            sql, (
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
            ),
        )


def _load_data(conn):
    mock_token_data = [(
        'token_cred', 'test token', 'token_comment', 'filename_located',
        '100', 'token_hash', 'other_factors', 'uuid',
    )]

    for token_data in mock_token_data:
        token_cred, token_type, token_comment, filename_located, \
            linenumber_located, token_hash, other_factors, uuid = (
                token_data
            )
        _insert_token_data(
            conn, token_cred, token_type, token_comment, filename_located,
            linenumber_located, token_hash, other_factors, uuid,
        )

    mock_commit_data = [
        (
            1, 'commit_hash', 'repo_name', 'branch_name', 'filename', 'linenumber',
            'author', f'author@{email_domain}', 'pusher', f'pusher@{email_domain}', 'committer',
            f'committer@{email_domain}', 'location_url', False, 'uniqueness_hash',
        ),
        (
            2, 'commit_hash', 'repo_name', 'branch_name', 'filename', 'linenumber',
            'author', f'author@{email_domain}', 'pusher', f'pusher@{email_domain}', 'committer',
            f'committer@{email_domain}', 'location_url', True, 'other_uniqueness_hash',
        ),
    ]

    for commit_data in mock_commit_data:
        token_id, hash, repo, branch, filename, linenumber, author_name, \
            author_email, pusher_username, pusher_email, committer_name, \
            committer_email, location_url, repo_public, uniqueness_hash = (commit_data)
        _insert_commit_data(
            conn, token_id, hash, repo, branch, filename, linenumber, author_name,
            author_email, pusher_username, pusher_email, committer_name,
            committer_email, location_url, repo_public, uniqueness_hash,
        )

    mock_vmt_report_data = [
        (
            'vuln_id', 'token_owner_email', 'token_type', 'vulnerability',
            'pusher_email', 'committer_email', 'author_email',
            '2020-01-01 08:45:00 UTC', '2020-01-01 08:45:00 UTC',
            'security_focals', True, True,
        ),
    ]
    for record in mock_vmt_report_data:
        vuln_id, token_owner_email, token_type, vulnerability, pusher_email, \
            committer_email, author_email, date_last_tested, date_remediated, \
            security_focals, repo_public, repo_private = (record)
        _insert_vmt_report_data(
            conn, vuln_id, token_owner_email, token_type, vulnerability, pusher_email,
            committer_email, author_email, date_last_tested, date_remediated,
            security_focals, repo_public, repo_private,
        )


def _get_conn():
    dbuser = 'postgres'
    dbhost = 'localhost'
    dbport = '54320'

    conn = psycopg2.connect(user=dbuser, host=dbhost, port=dbport)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    return conn


@pytest.fixture
def database(request):
    """Fixture to connect to local test DB"""

    conn = _get_conn()
    _recreate_tables(conn)

    yield conn

    conn.close()


@pytest.fixture
def database_with_data(request):
    """Fixture to connect to local test DB"""
    conn = _get_conn()
    _recreate_tables(conn)
    _load_data(conn)

    yield conn

    conn.close()
