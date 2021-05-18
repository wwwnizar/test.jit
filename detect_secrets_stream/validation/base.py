import abc
import json

from ..validation.validateException import ValidationException


class BaseValidator(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def validate(self, secret, other_factors) -> bool:  # pragma: no cover
        """ validate() should return True if the secret is active or False if it
        is inactive. validate() may raise a ValidationException if the secret's
        active status cannot be determined (i.e. VerifiedResult.UNVERIFIED). """
        raise NotImplementedError('Implement this')

    @abc.abstractmethod
    def revoke(self, secret, other_factors, secret_id) -> bool:
        """ Attempt to revoke the token and return a boolean indicating whether
        or not the revocation was successful. If revocation isn't to be
        implemented for the token type of the validator class, simply pass or
        return None. """
        raise NotImplementedError('Implement this')

    @abc.abstractmethod
    def resolve_owner(self, secret, other_factors):  # pragma: no cover
        raise NotImplementedError('Implement this')

    @staticmethod
    @abc.abstractmethod
    def secret_type_name():
        raise NotImplementedError('Implement this')

    @staticmethod
    def get_key_from_other_factors(key, other_factors):
        if not other_factors:
            raise ValidationException(f'other_factors "{other_factors}" is invalid')

        if type(other_factors) is str:
            try:
                other_factors = json.loads(other_factors)
            except Exception:
                raise ValidationException('Can not parse other factors as json')

        if key not in other_factors:
            raise ValidationException(f'Missing "{key}" field in other_factors')

        return other_factors[key]
