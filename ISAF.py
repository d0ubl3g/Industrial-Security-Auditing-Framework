#!/usr/bin/env python3

import argparse
import logging.handlers
import os
from colorama import init, Fore, Style

import Configuration
from Interpreters.ISAFInterpreter import ISAFInterpreter

# COLORAMA INIT #
init()

# LOGGER CONFIGURATION #
log_handler = logging.handlers.RotatingFileHandler(Configuration.LOG_FILE_NAME,
                                                   maxBytes=int(Configuration.LOG_MAX_FILE_SIZE))
log_format = logging.Formatter('%(asctime)s %(levelname)s %(name)s       %(message)s')
log_handler.setFormatter(log_format)
LOGGER = logging.getLogger()
LOGGER.setLevel(int(Configuration.LOG_LEVEL))
LOGGER.addHandler(log_handler)

# ARGUMENT PARSE #
parser = argparse.ArgumentParser(description=Style.BRIGHT + Fore.BLUE + 'ISAF - Industrial Security Auditing Framework' + Style.NORMAL + Fore.RESET)
parser.add_argument('-e',
                    '--extra-package-path',
                    help='Add extra modules to ISAF. (Overwrites Configured One)')


def ISAF(extra_package_path=Configuration.EXTRA_PACKAGE_PATH):
    if not os.path.isdir(extra_package_path):
        extra_package_path = None
    isaf = ISAFInterpreter(extra_package_path)
    isaf.start()


if __name__ == "__main__":
    args = parser.parse_args()
    if args.extra_package_path:
        ISAF(extra_package_path=args.extra_package_path)
    else:
        ISAF()
