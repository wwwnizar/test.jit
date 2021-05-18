import json
import os
import tempfile
from unittest import mock

import pytest

from detect_secrets_stream.notification.box_uploader import BoxClient


class TestBox:

    @pytest.fixture
    def box_client(self):
        return BoxClient()

    def test_upload_non_existed_file(self, box_client):
        with pytest.raises(Exception, match=r'not a regular file'):
            box_client.upload_file('id', 'some_randome_file')

    def test_upload_new(self, box_client):
        tmp_file = tempfile.NamedTemporaryFile()
        box_client.get_client = mock_client = mock.MagicMock()
        mock_client.folder.get.get_items.return_value = []

        box_client.upload_file('id', tmp_file.name)
        mock_client.file.assert_not_called()

    def test_re_upload(self, box_client):
        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file_id = 'fake_id'
        tmp_file_basename = os.path.basename(tmp_file.name)

        box_client.get_client = mock.MagicMock()
        box_client.get_client.return_value = mock_client = mock.MagicMock()
        print(f'mock_client={mock_client}')

        mock_folder = mock.MagicMock()

        class BoxItem:
            pass
        tmp_file_item = BoxItem()
        setattr(tmp_file_item, 'type', 'file')
        setattr(tmp_file_item, 'name', tmp_file_basename)
        setattr(tmp_file_item, 'object_id', tmp_file_id)
        mock_folder.get_items.return_value = [
            tmp_file_item,
        ]

        mock_get = mock.MagicMock()
        mock_get.get.return_value = mock_folder

        mock_client.folder.return_value = mock_get

        mock_file = mock.MagicMock()
        mock_client.file.return_value = mock_file

        box_client.upload_file('id', tmp_file.name)

        mock_client.file.assert_called_with(tmp_file_id)
        mock_file.update_contents.assert_called_with(tmp_file.name)

    def test_get_client_existed(self, box_client):
        mock_client = mock.MagicMock()
        box_client.client = mock_client
        assert box_client.get_client() == mock_client

    def test_get_client_new(self, box_client):
        # fake test key
        data = {
            'boxAppSettings': {
                'clientID': 'client_id',
                'clientSecret': 'client_secret',
                'appAuth': {
                    'publicKeyID': 'public_key_id',
                    'privateKey': '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIeUpp1nklqwUCAggA\nMBQGCCqGSIb3DQMHBAjayKyRaIDcWgSCBMhB8Ti10XeyGRm2JIPCE+/OtnuSEyT3\ni3190jYJS4gZ1iaAn9BusrmfHc5t+uau7i1O3x0I8UQjzwa8tAonCu4d6M2Vu8J+\nUuW1RnW03sKCR2tmZnZpgJMX+8TE8soAVy/CGeZ9onZ9Ct6/f0dVCzStuM4va039\nKymhoptWz2F0wq8Fg/i4F3/nfQ/LuIaQO8N65MIV7KdJmPC2ujwXCBZ4w4WRNY8M\nHPo/CtjiritFIXwsdZ4fXEHvWq6GhLivzp1/IimPrlwsKRXdjEtG1jPlnLHWNEOa\nigQw3HL1dEHbjNEj6O6cIae8BEsv698zHs9ZAnqUbj/Cr7NKsLptRqVmJ8PcsLni\n+Kb6YgUHbB6JsjtUFe/xIlvdUnkwT21ejAngoZL2mhR0WGHnLgADWuf8bdISk3RG\nevaPlnZfkEdD5JNGUeD46u3Eu74ViiVb2RtMTFwOePf0vIffIO7F9nh6L+ZWRORC\n2cd+21IH9tAYtgoZQBCblmaGbWF18Jh6/v6oKPT7uG1hJa3pCEpIJSeqbUv8O0PC\nV/XIGRF/vYj/AfZJFORYsiJ0cASICzGQ1vIyaZDnX7nC48PYBdNuCdZDnYQgFfRV\n1/VJwC+mPw+6P0jNWgHb28z8yPSrTcBe77XLjIaQFb06x23+ncjCS9HIBHLc7NOw\nv75c7itae2QvjUjtn3bYGuVyWAvixfrPXAlOIBA6e1IS+vqNjxA3jnUUOaS75qja\neSMSsEm312ovN/84xAVFXRZeasv/xAhI0S9F2VAq5rNcq23cKJfdWHFUmUDDvhkH\nRCGkdj5f0NpRyBEkU7ZGZG5vOUn1QP1w/SE+u+lGOCnU6K95aouvvmkO36KE+G3T\n2pWrtx/EhD1ODNfZcWhJSEWCnKf9UqrOFYZC8hpSMdWpWzHSebWFnZS9nQTPAv/O\ng0Ycw9M/7e9xSEtVZgZ8QS9a8w38eKyrmHKyml10xyxU3k0JMVIWeSwRrNkIQ20g\naOOigABLXA6IA0ah+0Ap9Ywm5sMcN7eCgRFXGVVDKQKNeHN+GHefLZCVunvb4t3K\nKABu17krvNS4lkGSmd/oe//o3BnQD0kj/Sqy2y6VSUTwcGK8lUNNUodtxHpDF/86\n7NFbufkyKjk17TNbnzYR0B8+q0yNxzje1zeTCk7DR08MiIfHB/tyvfrNz2BfhS+5\nU9rkJI24ZI20gEY74KAJ+SRwv3CZr5rBxhzGrWvarizC+eayLdjskMphsR7ZoYBT\nGrSKE1sfmgaR7nRNavY8nzcalf9dvF2tV7QO470SSaYSr9G9sFmKqa9kR56TvcvB\nKKwjtIOg/8h1lC9OlaNjQwaWtxiEW+lIapmtOAnDOlri5jA8vykDh+LqmzZG7ARe\nmrHVkZR1aGAgqoX76zcljhu1PYkNvKs/7p13BGxniU/O8NCI9XmszULSGqYNw0ZZ\n8tC6mZ26Lt5cqxJYEQ2+u9ffOqSIgoIg6ENcAHtiI8jBUgMiOSvMXKpFxRf53KbM\nVNxOoVLmAnvZX76GJE9hlO+T3cZ5Gm4k29iKWtlJ6YjQfMI3nuC0lr1wePxrVtY9\nRS5DE0B4T0IEgsRwzgxdLLUKTmO/9PGT6jH0/igOMGJh9mDmxQixyfyk8b/Awt7z\ndr8=\n-----END ENCRYPTED PRIVATE KEY-----\n',  # noqa E501
                    'passphrase': 'c70a11c1175aa17649bcc505004899b6',
                },
            },
            'enterpriseID': 'enterprise_id',
        }
        box_config_file = tempfile.NamedTemporaryFile(mode='w')
        json.dump(data, box_config_file)
        box_config_file.flush()

        client = box_client.get_client(box_config_file.name)
        assert client is not None
