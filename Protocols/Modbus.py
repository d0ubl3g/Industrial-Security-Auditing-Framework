from scapy.fields import *
from scapy.layers.inet import TCP
from scapy.packet import *


__info__ = {
    'name': 'Modbus Protocol',
    'authors': [
        'D0ubl3G <d0ubl3g[at]protonmail.com>',
    ],
    'description': 'Modbus protocol implementation.',
    'references': [
        'http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf',
    ]
}

functionCodes = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status (Serial Line Only)",
    0x08: "Diagnostics (Serial Line Only)",
    0x0B: "Get Comm Event Counter (Serial Line Only)",
    0x0C: "Get Comm Event Log (Serial Line Only)",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID (Serial Line Only)",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Encapsulated Interface Transport (MEI Needed)"
}

exceptionCodes = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge",
    0x06: "Server Device Busy",
    0x08: "Memory Parity Error",
    0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Device Failed to Respond"
}

meiCodes = {
    0x0D: "CANopen General Reference Request and Response PDU",
    0x0E: "Read Device Identification"
}

diagnosticsFunctions = {
    0x00: "Return Query Data",
    0x01: "Restart Communications Option",
    0x02: "Return Diagnostic Register",
    0x03: "Change ASCII Input Delimiter",
    0x04: "Force Listen Only Mode",
    0x05: "RESERVED",
    0x06: "RESERVED",
    0x07: "RESERVED",
    0x08: "RESERVED",
    0x09: "RESERVED",
    0x0A: "Clear Counters and Diagnostic Register",
    0x0B: "Return Bus Message Count",
    0x0C: "Return Bus Communication Error Count",
    0x0D: "Return Bus Exception Error Count",
    0x0E: "Return Server Message Count",
    0x0F: "Return Server No Response Count",
    0x10: "Return Server NAK Count",
    0x11: "Return Server Busy Count",
    0x12: "Return Bus Character Overrun Count",
    0x13: "RESERVED",
    0x14: "Clear Overrun Counter and Flag"
}

errorCodeBase = 0x80


def getDictValue(arr, value):
    for key, val in arr.items():
        if val is value:
            return key
        elif key == value:
            return val


class ReadCoilsRequest(Packet):
    name = getDictValue(functionCodes, 0x01) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Coils")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("coilsQty", 0x0001)]  # 0x0001 to 0x07D0


class ReadCoilsResponse(Packet):
    name = getDictValue(functionCodes, 0x01) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Coils")),
                   BitFieldLenField("byteCount", None, 8, count_of="coilStatus"),
                   FieldListField("coilStatus", [0x00], ByteField("", 0x00),
                                  count_from=lambda packet: packet.byteCount)]


class ReadCoilsError(Packet):
    name = getDictValue(functionCodes, 0x01) + " Error"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Coils") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadDiscreteInputsRequest(Packet):
    name = getDictValue(functionCodes, 0x02) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Discrete Inputs")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("inputQty", 0x0001)]  # 0x0001 to 0x07D0


class ReadDiscreteInputsResponse(Packet):
    name = getDictValue(functionCodes, 0x02) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Discrete Inputs")),
                   BitFieldLenField("byteCount", None, 8, count_of="inputStatus"),
                   FieldListField("inputStatus", [0x00], ByteField("", 0x00),
                                  count_from=lambda packet: packet.byteCount)]


class ReadDiscreteInputsError(Packet):
    name = getDictValue(functionCodes, 0x02) + " Error"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Discrete Inputs") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadHoldingRegistersRequest(Packet):
    name = getDictValue(functionCodes, 0x03) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Holding Registers")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("holdingRegisterQty", 0x0001)]  # 0x0001 to 0x007D


class ReadHoldingRegistersResponse(Packet):
    name = getDictValue(functionCodes, 0x03) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Holding Registers")),
                   BitFieldLenField("byteCount", None, 8, count_of="registerValue", adjust=lambda packet, x: x * 2),
                   FieldListField("registerValue", [0x0000], ShortField("", 0x0000),
                                  count_from=lambda packet: packet.byteCount)]


class ReadHoldingRegistersError(Packet):
    name = getDictValue(functionCodes, 0x03) + " Error"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Holding Registers") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadInputRegistersRequest(Packet):
    name = getDictValue(functionCodes, 0x04) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Input Registers")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("inputRegisterQty", 0x0001)]  # 0x0001 to 0x007D


class ReadInputRegistersResponse(Packet):
    name = getDictValue(functionCodes, 0x04) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Input Registers")),
                   BitFieldLenField("byteCount", None, 8, count_of="inputRegisters", adjust=lambda packet, x: x * 2),
                   FieldListField("inputRegisters", [0x0000], ShortField("", 0x0000),
                                  count_from=lambda packet: packet.byteCount)]


class ReadInputRegistersError(Packet):
    name = getDictValue(functionCodes, 0x04) + " Error"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Input Registers") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class WriteSingleCoilRequest(Packet):
    name = getDictValue(functionCodes, 0x05) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Write Single Coil")),
                   XShortField("outputAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("outputValue", 0x0000)]  # 0x0000 or 0xFF00


class WriteSingleCoilResponse(Packet):
    name = getDictValue(functionCodes, 0x05) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Write Single Coil")),
                   XShortField("outputAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("outputValue", 0x0000)]  # 0x0000 or 0xFF00


class WriteSingleCoilError(Packet):
    name = getDictValue(functionCodes, 0x05) + " Error"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Write Single Coil") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class WriteSingleRegisterRequest(Packet):
    name = getDictValue(functionCodes, 0x06) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Write Single Register")),
                   XShortField("registerAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("registerValue", 0x0000)]  # 0x0000 to 0xFFFF


class WriteSingleRegisterResponse(Packet):
    name = getDictValue(functionCodes, 0x06) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Write Single Register")),
                   XShortField("registerAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("registerValue", 0x0000)]  # 0x0000 to 0xFFFF


class WriteSingleRegisterError(Packet):
    name = getDictValue(functionCodes, 0x06) + " Error"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Write Single Register") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadExceptionStatusRequestSL(Packet):
    name = getDictValue(functionCodes, 0x07) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Exception Status (Serial Line Only)"))]


class ReadExceptionStatusResponseSL(Packet):
    name = getDictValue(functionCodes, 0x07) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Read Exception Status (Serial Line Only)")),
                   XByteField("outputData", 0x00)]  # 0x00 to 0xFF


class ReadExceptionStatusErrorSL(Packet):
    name = getDictValue(functionCodes, 0x07) + " Error"
    fields_desc = [XByteField("functionCode",
                              getDictValue(functionCodes, "Read Exception Status (Serial Line Only)") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


# TODO: Serial Line Diagnostics Packets
'''
class DiagnosticsRequestSL(Packet):
    name = getDictValue(functionCodes, 0x08) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Diagnostics (Serial Line Only)")),
                   XShortField("subFunctionCode", 0x00),
                   XShortField("data",)]
'''


class GetCommEventCounterRequestSL(Packet):
    name = getDictValue(functionCodes, 0x0B) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Get Comm Event Counter (Serial Line Only)"))]


class GetCommEventCounterResponseSL(Packet):
    name = getDictValue(functionCodes, 0x0B) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Get Comm Event Counter (Serial Line Only)")),
                   XShortField("status", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("eventCount", 0x0000)]  # 0x0000 to 0xFFFF


class GetCommEventCounterErrorSL(Packet):
    name = getDictValue(functionCodes, 0x0B) + " Error"
    fields_desc = [XByteField("functionCode",
                              getDictValue(functionCodes, "Read Exception Status (Serial Line Only)") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class GetCommEventLogRequestSL(Packet):
    name = getDictValue(functionCodes, 0x0C) + " Request"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Get Comm Event Log (Serial Line Only)"))]


class GetCommEventLogResponseSL(Packet):
    name = getDictValue(functionCodes, 0x0C) + " Response"
    fields_desc = [XByteField("functionCode", getDictValue(functionCodes, "Get Comm Event Log (Serial Line Only)")),
                   BitFieldLenField("byteCount", None, 8, count_of="events"),
                   XShortField("status", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("eventCount", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("messageCount", 0x0000),  # 0x0000 to 0xFFFF
                   FieldListField("events", [0x00], XByteField("", 0x00), count_from=lambda packet: packet.byteCount)]
