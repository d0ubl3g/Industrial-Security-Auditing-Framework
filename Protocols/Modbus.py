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
TYPE_REQUEST = " Request"
TYPE_RESPONSE = " Response"
TYPE_ERROR = " Error"


def getFunctionValue(value):
    for key, val in functionCodes.items():
        if val is value:
            return key
        elif key == value:
            return val


class ReadCoilsRequest(Packet):
    name = getFunctionValue(0x01) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Coils")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("coilsQty", 0x0001)]  # 0x0001 to 0x07D0


class ReadCoilsResponse(Packet):
    name = getFunctionValue(0x01) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Coils")),
                   BitFieldLenField("byteCount", None, 8, count_of="coilStatus"),
                   FieldListField("coilStatus", [0x00], XByteField("", 0x00),
                                  count_from=lambda p: p.byteCount)]


class ReadCoilsError(Packet):
    name = getFunctionValue(0x01) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Coils") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadDiscreteInputsRequest(Packet):
    name = getFunctionValue(0x02) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Discrete Inputs")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("inputQty", 0x0001)]  # 0x0001 to 0x07D0


class ReadDiscreteInputsResponse(Packet):
    name = getFunctionValue(0x02) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Discrete Inputs")),
                   BitFieldLenField("byteCount", None, 8, count_of="inputStatus"),
                   FieldListField("inputStatus", [0x00], XByteField("", 0x00),
                                  count_from=lambda p: p.byteCount)]


class ReadDiscreteInputsError(Packet):
    name = getFunctionValue(0x02) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Discrete Inputs") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadHoldingRegistersRequest(Packet):
    name = getFunctionValue(0x03) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Holding Registers")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("holdingRegisterQty", 0x0001)]  # 0x0001 to 0x007D


class ReadHoldingRegistersResponse(Packet):
    name = getFunctionValue(0x03) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Holding Registers")),
                   BitFieldLenField("byteCount", None, 8, count_of="registerValue", adjust=lambda packet, x: x * 2),
                   FieldListField("registerValue", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda p: p.byteCount)]


class ReadHoldingRegistersError(Packet):
    name = getFunctionValue(0x03) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Holding Registers") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadInputRegistersRequest(Packet):
    name = getFunctionValue(0x04) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Input Registers")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("inputTYPE_REQUESTRegisterQty", 0x0001)]  # 0x0001 to 0x007D


class ReadInputRegistersResponse(Packet):
    name = getFunctionValue(0x04) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Input Registers")),
                   BitFieldLenField("byteCount", None, 8, count_of="inputRegisters", adjust=lambda packet, x: x * 2),
                   FieldListField("inputRegisters", [0x0000], XShortField("", 0x0000),
                                  count_from=lambda p: p.byteCount)]


class ReadInputRegistersError(Packet):
    name = getFunctionValue(0x04) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Input Registers") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class WriteSingleCoilRequest(Packet):
    name = getFunctionValue(0x05) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Single Coil")),
                   XShortField("outputAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("outputValue", 0x0000)]  # 0x0000 or 0xFF00


class WriteSingleCoilResponse(Packet):
    name = getFunctionValue(0x05) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Single Coil")),
                   XShortField("outputAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("outputValue", 0x0000)]  # 0x0000 or 0xFF00


class WriteSingleCoilError(Packet):
    name = getFunctionValue(0x05) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Single Coil") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class WriteSingleRegisterRequest(Packet):
    name = getFunctionValue(0x06) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Single Register")),
                   XShortField("registerAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("registerValue", 0x0000)]  # 0x0000 to 0xFFFF


class WriteSingleRegisterResponse(Packet):
    name = getFunctionValue(0x06) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Single Register")),
                   XShortField("registerAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("registerValue", 0x0000)]  # 0x0000 to 0xFFFF


class WriteSingleRegisterError(Packet):
    name = getFunctionValue(0x06) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Single Register") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadExceptionStatusRequestSL(Packet):
    name = getFunctionValue(0x07) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Exception Status (Serial Line Only)"))]


class ReadExceptionStatusResponseSL(Packet):
    name = getFunctionValue(0x07) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Read Exception Status (Serial Line Only)")),
                   XByteField("outputData", 0x00)]  # 0x00 to 0xFF


class ReadExceptionStatusErrorSL(Packet):
    name = getFunctionValue(0x07) + TYPE_ERROR
    fields_desc = [XByteField("functionCode",
                              getFunctionValue("Read Exception Status (Serial Line Only)") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


# TODO: Serial Line Diagnostics Packets
'''
class DiagnosticsRequestSL(Packet):
    name = getDictValue(0x08) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getDictValue("Diagnostics (Serial Line Only)")),
                   XShortField("subFunctionCode", 0x00),
                   XShortField("data",)]
'''


class GetCommEventCounterRequestSL(Packet):
    name = getFunctionValue(0x0B) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Get Comm Event Counter (Serial Line Only)"))]


class GetCommEventCounterResponseSL(Packet):
    name = getFunctionValue(0x0B) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Get Comm Event Counter (Serial Line Only)")),
                   XShortField("status", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("eventCount", 0x0000)]  # 0x0000 to 0xFFFF


class GetCommEventCounterErrorSL(Packet):
    name = getFunctionValue(0x0B) + TYPE_ERROR
    fields_desc = [XByteField("functionCode",
                              getFunctionValue("Get Comm Event Counter (Serial Line Only)") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class GetCommEventLogRequestSL(Packet):
    name = getFunctionValue(0x0C) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Get Comm Event Log (Serial Line Only)"))]


class GetCommEventLogResponseSL(Packet):
    name = getFunctionValue(0x0C) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Get Comm Event Log (Serial Line Only)")),
                   BitFieldLenField("byteCount", None, 8, count_of="events"),
                   XShortField("status", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("eventCount", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("messageCount", 0x0000),  # 0x0000 to 0xFFFF
                   FieldListField("events", [0x00], XByteField("", 0x00), count_from=lambda p: p.byteCount)]


class GetCommEventLogErrorSL(Packet):
    name = getFunctionValue(0x0C) + TYPE_ERROR
    fields_desc = [XByteField("functionCode",
                              getFunctionValue("Get Comm Event Log (Serial Line Only)") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class WriteMultipleCoilsRequest(Packet):
    name = getFunctionValue(0x0F) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Multiple Coils")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("outputQty", 0x0001),  # 0x0001 to 0x07B0
                   BitFieldLenField("byteCount", None, 8, count_of="outputsValue"),
                   FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from=lambda p: p.byteCount)]


class WriteMultipleCoilsResponse(Packet):
    name = getFunctionValue(0x0F) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Multiple Coils")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("outputQty", 0x0001)]  # 0x0001 to 0x07B0


class WriteMultipleCoilsError(Packet):
    name = getFunctionValue(0x0F) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Multiple Coils") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class WriteMultipleRegistersRequest(Packet):
    name = getFunctionValue(0x10) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Multiple Registers")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   BitFieldLenField("registerQty", None, 16, count_of="registersValue",),  # 0x0001 to 0x007B
                   BitFieldLenField("byteCount", None, 8, count_of="registersValue", adjust=lambda p, x: x * 2),
                   FieldListField("registersValue", [0x0000], XShortField("", 0x00), count_from=lambda p: p.byteCount)]


class WriteMultipleRegistersResponse(Packet):
    name = getFunctionValue(0x10) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Multiple Registers")),
                   XShortField("startingAddress", 0x0000),  # 0x0000 to 0xFFFF
                   XShortField("registersQty", 0x0001)]  # 0x0001 to 0x007B


class WriteMultipleRegistersError(Packet):
    name = getFunctionValue(0x10) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Write Multiple Registers") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReportServerIDRequestSL(Packet):
    name = getFunctionValue(0x11) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Report Server ID (Serial Line Only)"))]


class ReportServerIDResponseSL(Packet):
    name = getFunctionValue(0x11) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Report Server ID (Serial Line Only)")),
                   BitFieldLenField("byteCount", None, 8, length_of="serverID"),
                   ConditionalField(StrLenField("serverID", "", length_from=lambda p: p.byteCount),
                                    lambda p: p.byteCount > 0),
                   ConditionalField(XByteField("runIndicatorStatus", 0x00), lambda p: p.byteCount > 0)]
    

class ReportServerIDErrorSL(Packet):
    name = getFunctionValue(0x11) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Report Server ID (Serial Line Only)") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class ReadFileRecordSubRequest(Packet):
    name = getFunctionValue(0x14) + " Sub Request"
    fields_desc = [XByteField("referenceType", 0x06),
                   XShortField("fileNumber", 0x0001),  # 0x0001 to 0xFFFF
                   XShortField("recordNumber", 0x0000),  # 0x0000 to 0x270F
                   XShortField("recordLength", 0x0001)]


class ReadFileRecordRequest(Packet):
    name = getFunctionValue(0x14) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Read File Record")),
                   XByteField("byteCount", None)]  # 0x07 to 0xF5
    # TODO: POST BUILD
    

class ReadFileRecordSubResponse(Packet):
    name = getFunctionValue(0x14) + " Sub Response"
    fields_desc = [BitFieldLenField("fileRespLength", None, 8, count_of="recordData", adjust=lambda p, x: (x * 2) + 1),
                   XByteField("referenceType", 0x06),
                   FieldListField("recordData", [0x0000], XShortField("", 0x0000), 
                                  count_from=lambda p: (p.fileRespLength - 1) // 2)]


class ReadFileRecordResponse(Packet):
    name = getFunctionValue(0x14) + TYPE_RESPONSE
    fields_desc = [XByteField("functionCode", getFunctionValue("Read File Record")),
                   XByteField("dataLength", None)]  # 0x07 to 0xF5
    # TODO: POST BUILD


class ReadFileRecordError(Packet):
    name = getFunctionValue(0x14) + TYPE_ERROR
    fields_desc = [XByteField("functionCode", getFunctionValue("Read File Record") + errorCodeBase),
                   ByteEnumField("exceptionCode", 1, exceptionCodes)]


class WriteFileRecordSubRequest(Packet):
    name = getFunctionValue(0x15) + " Sub Request"
    fields_desc = [XByteField("referenceType", 0x06),
                   XShortField("fileNumber", 0x0001),  # 0x0001 to 0xFFFF
                   XShortField("recordNumber", 0x0000),  # 0x0000 to 0x270F
                   BitFieldLenField("recordLength", None, 16, length_of="recordData", adjust=lambda p, x: x // 2),
                   FieldListField("recordData", [0x0000], XShortField("", 0x0000),
                                  length_from=lambda p: p.recordLength * 2)]


class WriteFileRecordRequest(Packet):
    name = getFunctionValue(0x15) + TYPE_REQUEST
    fields_desc = [XByteField("functionCode", getFunctionValue("Write File Record")),
                   XByteField("dataLength", None)]  # 0x09 to 0xFB
    # TODO: POST BUILD
