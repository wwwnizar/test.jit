import logging

import logmatic


class LogUtil():

    @staticmethod
    def get_root_logger():
        return logging.getLogger(__name__.split('.')[0])

    @staticmethod
    def get_main_logger():
        return logging.getLogger('__main__')

    @staticmethod
    def set_root_logger_json():
        # Configure on top level logger detect_secrets_stream
        # the setting would be propagated to all children, such as detect_secrets_stream.xx.xx
        for logger in (LogUtil.get_main_logger(), LogUtil.get_root_logger()):
            logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            handler.setFormatter(logmatic.JsonFormatter())
            logger.addHandler(handler)

    @staticmethod
    def set_root_logger_console():
        # Configure on top level logger detect_secrets_stream
        # the setting would be propagated to all children, such as detect_secrets_stream.xx.xx
        for logger in (LogUtil.get_main_logger(), LogUtil.get_root_logger()):
            logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            logger.addHandler(handler)
