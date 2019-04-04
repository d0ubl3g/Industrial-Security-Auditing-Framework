import configparser

config = configparser.ConfigParser()
config.read('ISAF.conf')

# LOG CONFIGURATION #
LOG_FILE_NAME = config['LOG']['filename']
LOG_MAX_FILE_SIZE = config['LOG']['max_filesize']
LOG_LEVEL = config['LOG']['level']
