import pytest

from detect_secrets_stream.security.security import Decryptor
from detect_secrets_stream.security.security import DeterministicCryptor
from detect_secrets_stream.security.security import Encryptor


class TestSecurity:

    def test_encrypt_none(self):
        encryptor = Encryptor()
        encrypted_text = encryptor.encrypt(None)
        assert encrypted_text is None

    def test_decrypt_none(self):
        decryptor = Decryptor()
        decrypted_text = decryptor.decrypt(None)
        assert decrypted_text is None

    def test_encrypt_decrypt(self):
        encryptor = Encryptor()
        decryptor = Decryptor()
        text = 'sometext'
        encrypted_text = encryptor.encrypt(text)
        assert type(encrypted_text) is bytes
        decrypted_text = decryptor.decrypt(encrypted_text)
        assert type(decrypted_text) is str
        assert decrypted_text == text

    def test_encrypt_diff_results(self):
        encryptor = Encryptor()
        text = 'sometext'
        encrypted_text_b1 = encryptor.encrypt(text)
        encrypted_text_b2 = encryptor.encrypt(text)
        assert encrypted_text_b1 != encrypted_text_b2
        assert str(encrypted_text_b1) != str(encrypted_text_b2)
        assert text != encrypted_text_b1
        assert text != encrypted_text_b2

    @pytest.mark.parametrize(
        ('text'),
        [
            '',
            'a',
            'a secret message',
            'a secret message1',
            'a secret message diff length',
            'a secret message with loooooong length',
        ],
    )
    def test_symmetric_encrypt_same_results(self, text):
        symmetric_key = DeterministicCryptor()

        encrypted_text_b1 = symmetric_key.encrypt(text)
        encrypted_text_b2 = symmetric_key.encrypt(text)
        assert encrypted_text_b1 == encrypted_text_b2
        assert str(encrypted_text_b1) == str(encrypted_text_b2)
        assert text != encrypted_text_b1
        assert text != encrypted_text_b2

    @pytest.mark.parametrize(
        ('text'),
        [
            '',
            'a',
            'a secret message',
            'a secret message1',
            'a secret message diff length',
            'a secret message with loooooong length',
        ],
    )
    def test_symmetric_encrypt_decrypt(self, text):
        symmetric_key = DeterministicCryptor()

        encrypted_text = symmetric_key.encrypt(text)
        assert type(encrypted_text) is bytes
        decrypted_text = symmetric_key.decrypt(encrypted_text)
        assert type(decrypted_text) is str
        assert decrypted_text == text

    def test_symmetric_encrypt_none(self):
        symmetric_key = DeterministicCryptor()
        encrypted_text = symmetric_key.encrypt(None)
        assert encrypted_text is None

    def test_symmetric_decrypt_none(self):
        symmetric_key = DeterministicCryptor()
        decrypted_text = symmetric_key.decrypt(None)
        assert decrypted_text is None
