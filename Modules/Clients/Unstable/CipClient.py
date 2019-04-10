from scapy.supersocket import StreamSocket

from Modules.Clients.Unstable.BaseClient import Base
from Protocols.Unstable.Cip import *
from Protocols.Unstable.Enip import *

from Base.Exploits import Option


class Exploit(Base):
    __info__ = {
        'name': 'clients/cip',
        'display_name': 'CIP Client',
        'description': '',
        'authors': [
            'D0ubl3G <d0ubl3g[at]protonmail.com>',
        ],
        'references': [
            '',
        ],
        'devices': [
            'Multi',
        ],
    }

    target = Option('', 'Target IP address')
    port = Option(44818, 'Target port')
    timeout = Option(2, 'Connection timeout')

    def __init__(self, name=""):
        if name is not None:
            super(Exploit, self).__init__(name)
        else:
            super(Exploit, self).__init__('CipClient')
        self._connection = None
        self._target_info = {}
        self._session = 0x0
        self.target_info = {}

    def run(self):
        self.connect()

    def connect(self):
        sock = socket.socket()
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))
        self._connection = StreamSocket(sock, Raw)
        packet_1 = ENIPHeader(Command=0x65) / RegisterSession()
        rsp_1 = self.send_receive_cip_packet(packet_1)
        try:
            if rsp_1.haslayer(ENIPHeader):
                self._session = rsp_1.Session
        except Exception as err:
            self.logger.error(err)
            return

    def reconnect(self):
        self.connect()

    def _fix_session(self, packet):
        try:
            packet.Session = self._session
            return packet
        except Exception as err:
            self.logger.error(err)
            return packet

    def send_packet(self, packet):
        if self._connection:
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_packet(self, packet):
        if self._connection:
            try:
                rsp = self._connection.sr1(packet, timeout=self.timeout)
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before receive packet!")

    def send_cip_packet(self, packet):
        if self._connection:
            packet = self._fix_session(packet)
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None
        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_cip_packet(self, packet):
        if self._connection:
            packet = self._fix_session(packet)
            # packet.show2()
            try:
                rsp = self._connection.sr1(packet, timeout=self.timeout)
                if rsp:
                    rsp = ENIPHeader(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_cip_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                if rsp:
                    rsp = ENIPHeader(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None
        else:
            self.logger.error("Please create connect before receive packet!")

    def get_target_info(self, port=0x01, port_segment=0x00):
        product_name = ''
        device_type = ''
        vendor = ''
        revision = ''
        serial_number = ''
        info_packet = ENIPHeader(Command=0x6f) / CIPCommandSpecificData() / \
                      CIPHeader(Type="Request", Service=0x52, ) / \
                      CIPConnectionManager()
        info_packet[CIPCommandSpecificData].Items = [NullAddressItem(), UnconnectedDataItem()]
        info_packet[CIPHeader].RequestPath = [CIPRequestPath(PathSegmentType=1, InstanceSegment=0x06),
                                              CIPRequestPath(PathSegmentType=1, LogicalSegmentType=0x01,
                                                             InstanceSegment=0x01)
                                              ]
        info_packet[CIPConnectionManager].MessageRequest = CIPHeader(Type="Request", Service=0x01,
                                                                     RequestPath=[
                                                                         CIPRequestPath(PathSegmentType=1,
                                                                                        InstanceSegment=0x01),
                                                                         CIPRequestPath(PathSegmentType=1,
                                                                                        LogicalSegmentType=0x01,
                                                                                        InstanceSegment=0x01)
                                                                     ])
        info_packet[CIPRoutePath].Port = port
        info_packet[CIPRoutePath].PortSegment = port_segment
        rsp = self.send_receive_cip_packet(info_packet)
        if rsp.haslayer(CIPHeader):
            if rsp[CIPHeader].GeneralStatus == 0x00:
                try:
                    if rsp.haslayer(GetAttributesAll):
                        product_name = rsp[GetAttributesAll].ProductName
                        device_type = rsp[GetAttributesAll].DeviceType
                        if device_type in DEVICE_TYPES.keys():
                            device_type = DEVICE_TYPES[device_type]
                        else:
                            device_type = "%s (%s)" % (product_name, hex(device_type))
                        vendor = rsp[GetAttributesAll].VendorID
                        if vendor in VENDOR_IDS.keys():
                            vendor = VENDOR_IDS[vendor]
                        else:
                            vendor = "%s (%s)" % (product_name, hex(vendor))
                        revision = str(rsp[GetAttributesAll].MajorRevision) + '.' \
                                   + str(rsp[GetAttributesAll].MinorRevision)
                        serial_number = hex(rsp[GetAttributesAll].SerialNumber)
                except Exception as err:
                    pass

            else:
                self.logger.warning("Got Error Code:%s when get target info with port:%s and port_segment:%s" %
                                    (port, port_segment, rsp[CIPHeader].GeneralStatus))
        return product_name, device_type, vendor, revision, serial_number
