import pkg_resources

ftp_defaults = 'file://' + pkg_resources.resource_filename(__name__, 'ftp_defaults_combo.txt')
telnet_defaults = 'file://' + pkg_resources.resource_filename(__name__, 'telnet_defaults_combo.txt')
defaults = 'file://' + pkg_resources.resource_filename(__name__, 'defaults.txt')
passwords = 'file://' + pkg_resources.resource_filename(__name__, 'passwords.txt')
usernames = 'file://' + pkg_resources.resource_filename(__name__, 'usernames.txt')
snmp = 'file://' + pkg_resources.resource_filename(__name__, 'snmp.txt')
