import os

import pytest

from detect_secrets_stream.scan_worker.hasher import Hasher


@pytest.fixture
def hasher_obj():
    return Hasher(os.getenv('GD_HMAC_KEY_FILENAME'))


def test_hash(hasher_obj):
    input = 'some testy test text'
    output = hasher_obj.hash(input)

    assert output is not None
    assert output != input
    assert type(output) == str


def test_hash_input_none(hasher_obj):
    input = None
    output = hasher_obj.hash(input)

    assert output == ''


def test_hash_is_deterministic(hasher_obj):
    input = 'some testy test text'

    output_1 = hasher_obj.hash(input)
    output_2 = hasher_obj.hash(input)
    assert output_1 == output_2
