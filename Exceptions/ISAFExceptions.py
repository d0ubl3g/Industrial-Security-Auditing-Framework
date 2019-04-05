import logging

LOGGER = logging.getLogger(__name__)


class ISAFException(Exception):
    def __init__(self, msg=''):
        super(ISAFException, self).__init__(msg)
        LOGGER.exception(self)


class OptionValidationError(ISAFException):
    pass


class StopThreadPoolExecutor(ISAFException):
    pass
