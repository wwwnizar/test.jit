import inspect
import os
import pkgutil
from importlib import import_module

from ..validation import base


class ValidatorFactory(object):

    validator_dict = {}

    @staticmethod
    def _init_validator_dict():
        """
        Automatically load all BaseValidator subclasses in current folder

        1. load all modules within current folder
        2. find all classes within each module
        3. validate class and initilize it
        """
        # avoid repeatablly load dict
        if ValidatorFactory.validator_dict:
            return

        pkgpath = os.path.dirname(base.__file__)
        basename = os.path.basename(__file__).split('.')[0]
        module_names = [
            name
            for _, name, ispkg in pkgutil.iter_modules([pkgpath])
            if ispkg is False and name != basename
        ]

        for module_name in module_names:
            module = import_module(f'detect_secrets_stream.validation.{module_name}')

            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, base.BaseValidator) and obj != base.BaseValidator:
                    klass = obj
                    ValidatorFactory.validator_dict[klass.secret_type_name()] = klass

    @staticmethod
    def get_validator(secret_type):
        ValidatorFactory._init_validator_dict()

        validator = None
        klass = ValidatorFactory.validator_dict.get(secret_type)
        if klass:
            validator = klass()

        return validator
