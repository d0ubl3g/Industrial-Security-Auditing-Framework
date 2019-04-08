import nmap
from Base import Validators
from Base.Exploits import Exploit, Option
from Utils import print_error, print_success, printTable

TABLE_HEADER = ["IPv4", "MAC", "Vendor"]


class Exploit(Exploit):
    __info__ = {
        'name': 'discovery/safe',
        'display_name': 'Safe ARP Host Discovery',
        'authors': [
            'D0ubl3G <d0ubl3g[at]protonmail.com>',
        ],
        'description': 'Safe host discovery using ARP Scan.',
        'references': [
            '',
        ],
        'devices': [
            'Multi'
        ],
    }

    result = []
    target = Option('192.168.1.0/24', "String for hosts as nmap use it 'scanme.nmap.org'"
                                      " or '198.116.0-255.1-127' or '216.163.128.20/20'", validators=Validators.ipv4)

    def run(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=self.target, arguments='-n -PR -sn ')
            for host in nm.all_hosts():
                try:
                    ipv4 = nm[host]['addresses']['ipv4']
                    mac = nm[host]['addresses']['mac']
                    vendor = nm[host]['vendor'][mac]
                except Exception as e:
                    if 'mac' in str(e):
                        mac = 'Unknown'
                        vendor = 'Unknown'
                    if 'vendor' in str(e):
                        vendor = 'Unknown'
                finally:
                    self.result.append([ipv4, mac, vendor])
                    ipv4 = ""
                    mac = ""
                    vendor = ""
            unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
            unique_device = sorted(unique_device, key=lambda x: (x[0], x[1]))
            if len(self.result) > 0:
                print_success("Found %s devices." % len(self.result))
                printTable(TABLE_HEADER, *unique_device, **{'max_column_length': 50})
                print('\r')
                self.result = []
            else:
                print_error("Didn't find any device on network %s" % self.target)
        except:
            print_error("Discovery Error. Aborting.")
