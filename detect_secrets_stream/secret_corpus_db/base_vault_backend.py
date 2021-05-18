from abc import ABC
from abc import abstractmethod


class BaseVaultBackend(ABC):
    """ Abstract base class for enforcing parity between Vault backend wrapper classes. """

    @abstractmethod
    def create_or_update_secret(self, token_id: int, secret: str, other_factors=None):
        """ Creates secret if doesn't exist, updates it if it does.

        Accepts: token_id: int, corresponds with the token_id in database
                 secret: str, the secret to write
                 other_factors: dict, secondary multifactors to write
        Returns: status code or create/update result from vault backend """
        raise NotImplementedError

    @abstractmethod
    def read_secret(self, token_id: int):
        """ Reads the secret with the given token_id from vault.
        Accepts: token_id: int, corresponds with the token_id in database
        Returns: dict containing secret, potentially other factors.
        Throws: VaultReadException if secret not in vault or other error encountered. """
        raise NotImplementedError
