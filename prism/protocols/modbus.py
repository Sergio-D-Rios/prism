from scapy.utils import RawPcapNgReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import scapy.contrib.modbus as mb
from prism.machine import Machine

_conversation_types = {
    1: 'reader',
    2: 'writer',
    3: 'processor',
    4: 'not_implemented'
}

_machine_classifications = {
    1: 'PLC',
    2: 'HMI',
    3: 'Alarm',
    4: 'Undefined'
}

def modbus_filter(pcap_file):
    # Here we need to do the standard filter based specifically for Modbus 
    # and return the list filtered packets
    pckts_of_interest = []

    for (packet_data, packet_metadata) in RawPcapNgReader(pcap_file):
        # Create the ethernet header for processed packet
        ethernet_packet = Ether(packet_data)

        # Only interested in IP/TCP packets the rest are ignored
        try:
            # Filter by known MAC Schemes of ICS devices here
            ip_packet = ethernet_packet[IP]
            tcp_packet = ip_packet[TCP]

            # Select only Modbus packets
            if tcp_packet.sport == 502 or tcp_packet.dport == 502:
                if (mb.ModbusADURequest in tcp_packet
                        or mb.ModbusADUResponse in tcp_packet):
                    pckts_of_interest.append(ethernet_packet)
            
        except Exception as err:
            print(err)
            continue

    return pckts_of_interest


def modbus_sort(packets):
    machines = []
    for packet in packets:
        ip_packet = packet[IP]
        curr_machine = None
    
        # Here we first need to check if the IP has been seen before, if
        # not append it to the machine list and populate it's initial data
        for machine in machines:
            if machine.ip == ip_packet.src:
                curr_machine = machine
                break
        else:
            # New Machine found
            curr_machine = Machine(ip_packet.src)
            machines.append(curr_machine)

        # check if the protocol has been seen before with this IP
        # Protocol here is based off of the protocol filter currently just 
        # checking modbus
        tcp_packet = ip_packet[TCP]

        # If modbus detected add it to machine's known protocols
        if tcp_packet.sport == 502 or tcp_packet.dport == 502:
            if not 'modbus' in curr_machine.protocols:
                curr_machine.protocols.append('modbus') 

            # check if associated IP has been seen before with this machine
            if not ip_packet.dst in curr_machine.associated_machines:
                curr_machine.associated_machines.append(ip_packet.dst)
            
            # Depending on the type of protocol, we want to determine the 
            # behavior of the packet
            conversation_type = modbus_type(tcp_packet)
            if not conversation_type in curr_machine.conversation_types:
                curr_machine.conversation_types.append(conversation_type)

            # check if this conversation has been seen before
            conversation = (ip_packet.src, 
                            ip_packet.dst, 
                            'modbus', 
                            conversation_type)
            if not conversation in curr_machine.conversations:
                curr_machine.conversations.append(conversation)

    return machines

def modbus_classify(machines): 
    for machine in machines:
        # Here we analyze each machine and classify it dependent on the
        # protocol and type of communication
        if 'modbus'in machine.protocols:
            if 'processor' in machine.conversation_types:
                machine.classification = _machine_classifications[1]
                print("Found a Processor")

            elif ('reader' in machine.conversation_types and
                    'writer' in machine.conversation_types):
                machine.classification = _machine_classifications[2]
                print("Found an HMI/Engineer's Computer")

            elif 'reader' in machine.conversation_types:
                machine.classification = _machine_classifications[3]
                print("Found an Alarm")

            else:
                machine.classification = _machine_classifications[4]
                print("Found an Undefined device!")

    return machines

def modbus_type(tcp_packet):
    mb_packet = tcp_packet['ModbusADU']

    if mb.ModbusADURequest in mb_packet:         
        if mb.ModbusPDU01ReadCoilsRequest in mb_packet:
            return _conversation_types[1]
        if mb.ModbusPDU02ReadDiscreteInputsRequest in mb_packet:
            return _conversation_types[1]
        if mb.ModbusPDU03ReadHoldingRegistersRequest in mb_packet:
            return _conversation_types[1]
        if mb.ModbusPDU04ReadInputRegistersRequest in mb_packet:
            return _conversation_types[1]
        if mb.ModbusPDU05WriteSingleCoilRequest in mb_packet:
            return _conversation_types[2]
        if mb.ModbusPDU06WriteSingleRegisterRequest in mb_packet:
            return _conversation_types[2]
        if mb.ModbusPDU0FWriteMultipleCoilsRequest in mb_packet:
            return _conversation_types[2]
        if mb.ModbusPDU11ReportSlaveIdRequest in mb_packet:
            return _conversation_types[1]
        if mb.ModbusPDU17ReadWriteMultipleRegistersRequest in mb_packet:
            return _conversation_types[2]
        return _conversation_types[4]
        
    if mb.ModbusADUResponse in mb_packet:
        if mb.ModbusPDU01ReadCoilsResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU02ReadDiscreteInputsResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU03ReadHoldingRegistersResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU04ReadInputRegistersResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU05WriteSingleCoilResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU06WriteSingleRegisterResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU0FWriteMultipleCoilsResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU11ReportSlaveIdResponse in mb_packet:
            return _conversation_types[3]
        if mb.ModbusPDU17ReadWriteMultipleRegistersResponse in mb_packet:
            return _conversation_types[3]
        return _conversation_types[4]