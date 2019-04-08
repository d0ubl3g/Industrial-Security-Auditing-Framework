import subprocess
import time
from Base import Validators
from Base.Exploits import Exploit, Option
from Utils import print_error, print_success, printTable

TABLE_HEADER = ["IPv4", "MAC", "Packet Qty", "Length", "Vendor"]


class Exploit(Exploit):
    __info__ = {
        'name': 'discovery/passive',
        'display_name': 'Passive ARP Host Discovery',
        'authors': [
            'D0ubl3G <d0ubl3g[at]protonmail.com>',
        ],
        'description': 'Passive host discovery using ARP Scan.',
        'references': [
            '',
        ],
        'devices': [
            'Multi'
        ],
    }

    result = []
    target = Option('', "Target IP range ex 192.168.0.0/24 /16 /8. "
                                      "Empty for auto mode.",
                    validators=Validators.ipv4)
    iface = Option('eth0', "Interface for ARP packet capture.")
    timeout = Option(15, 'Capture timeout in seconds.')

    def run(self):
        try:
            try:
                if self.target is "":
                    p = subprocess.Popen(['netdiscover', '-i', self.iface, '-p', '-P', '-N'], stdout=subprocess.PIPE)
                else:
                    p = subprocess.Popen(['netdiscover', '-i', self.iface, '-r', self.target, '-p', '-P', '-N'],
                                         stdout=subprocess.PIPE)
                output, error = p.communicate(timeout=self.timeout)
            except:
                p.kill()
                output, error = p.communicate()

            for x in output.decode().split('\n'):
                if x is not "":
                    if len(x.split()) >= 5:
                        self.result.append([x.split()[0],x.split()[1],x.split()[2], x.split()[3], " ".join(x.split()[4:])])
                    else:
                        self.result.append([x.split()[0], x.split()[1], x.split()[2], x.split()[3], ""])
            unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
            unique_device = sorted(unique_device, key=lambda x: (x[0], x[1]))
            if len(self.result) > 0:
                print_success("Found %s devices." % len(self.result))
                printTable(TABLE_HEADER, *unique_device, **{'max_column_length': 50})
                print('\r')
                self.result = []
            else:
                print_error("Didn't find any device on network %s" % self.target)
        except Exception as e:
            print_error(e)
            print_error("Discovery Error. Aborting. May increase timeout.")
