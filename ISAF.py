#!/usr/bin/env python3

import Configuration
import logging.handlers

# LOGGER CONFIGURATION #
log_handler = logging.handlers.RotatingFileHandler(Configuration.LOG_FILE_NAME, maxBytes=Configuration.LOG_MAX_FILE_SIZE)
log_format = logging.Formatter('%(asctime)s %(levelname)s %(name)s       %(message)s')
log_handler.setFormatter(log_format)
LOGGER = logging.getLogger()
LOGGER.setLevel(Configuration.LOG_LEVEL)
LOGGER.addHandler(log_handler)

