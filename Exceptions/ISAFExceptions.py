import logging

LOGGER = logging.getLogger(__name__)


def ISAFException(Exception):
    def __init__(self, msg=''):
        super(ISAFException, self).__init__(msg)
        LOGGER.exception(self)
