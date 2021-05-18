from detect_secrets_stream.validation.factory import ValidatorFactory
from detect_secrets_stream.validation.slack import SlackValidator


class TestFactory:

    def test_get_klass(self):
        validator = ValidatorFactory.get_validator(SlackValidator.secret_type_name())
        assert isinstance(validator, SlackValidator)
