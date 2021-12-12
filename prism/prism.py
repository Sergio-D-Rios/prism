from scapy.utils import RawPcapNgReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import scapy.contrib.modbus as mb
from prism.machine import Machine
from prism.visualizer import Visualizer
from prism.protocols.modbus import modbus_filter, modbus_sort, modbus_classify
from prism.protocols.s7comm import s7comm_filter, s7comm_sort, s7comm_classify
from prism.protocols.cip import cip_filter, cip_sort, cip_classify
from prism.protocols.bacnet import bacnet_filter, bacnet_sort, bacnet_classify
import json
import os
import sys

_machine_classifications = {
    1: 'PLC',
    2: 'HMI',
    3: 'Alarm',
    4: 'Undefined'
}

_conversation_types = {
    1: 'reader',
    2: 'writer',
    3: 'processor',
    4: 'not_implemented'
}

_supported_protocols = [
    'modbus',
    's7comm',
    'cip',
    'bacnet'
]

class Prism():

    def __init__(self, 
                 pcap_file: str=None, 
                 protocol_filters: list=['modbus'], 
                 input_file: str=None,
                 output_file: str=None,
                 visualize: bool=False):
        self.pcap_file = pcap_file
        self.protocol_filters = protocol_filters
        self.input_file = input_file
        self.output_file = output_file
        self.visualize_flag = visualize
        self.machines = []
        self.packets = []


    def launch(self):
        if self.input_file != None:
            # Make sure that the pcap file provided is usable
            if not os.path.isfile(self.input_file):
                print(f"Unable to open the file: {self.input_file}", 
                      file=sys.stderr)

            self.process_input()

        elif self.pcap_file != None:
            # Make sure that the pcap file provided is usable
            if not os.path.isfile(self.pcap_file):
                print(f"Unable to open the file: {self.pcap_file}", 
                      file=sys.stderr)

            self.pcap_filter()
            self.pcap_sorter()
            self.pcap_classifier()

        for machine in self.machines:
            print(machine.ip)
            print(machine.protocols)
            print(machine.conversation_types)
            print(machine.associated_machines)
            for conversation in machine.conversations:
                print(conversation)
            print(machine.classification)

        if self.output_file != None:
            self.create_output()
        
        if self.visualize_flag:
            self.visualizer()


    def pcap_filter(self):
        # Check that passed in filters are usable
        for filter in self.protocol_filters:
            if filter not in _supported_protocols:
                print(f"{filter} is not a supported protocol!")
                exit()

        # FIXME: Not that opening the PCAP again and again is not 
        # the most efficient 

        # Filter by desired ICS protocol here 
        if 'modbus' in self.protocol_filters:
            self.packets.extend(modbus_filter(self.pcap_file))
        elif 's7comm' in self.protocol_filters:
            print('s7comm not yet supported')
            exit()
        elif 'cip' in self.protocol_filters:
            print('cip not yet supported')
            exit()
        elif 'bacnet' in self.protocol_filters:
            print('bacnet not yet supported')
            exit()
         
           
    def pcap_sorter(self):
        for packet in self.packets:
            ip_packet = packet[IP]
            curr_machine = {}
            protocol = ""
        
            # Here we first need to check if the IP has been seen before, if
            # not append it to the machine list and populate it's initial data
            for machine in self.machines:
                if machine.ip == ip_packet.src:
                    curr_machine = machine
                    break
            else:
                # New Machine found
                curr_machine = Machine(ip_packet.src)
                self.machines.append(curr_machine)

            # check if the protocol has been seen before with this IP
            # Protocol here is based off of the protocol filter currently just 
            # checking modbus
            tcp_packet = ip_packet[TCP]

            # If modbus detected add it to machine's known protocols
            if tcp_packet.sport == 502 or tcp_packet.dport == 502:
                if not 'modbus' in curr_machine.protocols:
                    curr_machine.protocols.append('modbus') 
                protocol = 'modbus'

            # check if associated IP has been seen before with this machine
            if not ip_packet.dst in curr_machine.associated_machines:
                curr_machine.associated_machines.append(ip_packet.dst)
            
            # Depending on the type of protocol, we want to determine the 
            # behavior of the packet
            if protocol == 'modbus':
                conversation_type = self.modbus_type(tcp_packet)

            if not conversation_type in curr_machine.conversation_types:
                curr_machine.conversation_types.append(conversation_type)

            conversation = (ip_packet.src, 
                            ip_packet.dst, 
                            protocol, 
                            conversation_type)

            # check if this conversation has been seen before
            if not conversation in curr_machine.conversations:
                curr_machine.conversations.append(conversation)


    def pcap_classifier(self):
        for machine in self.machines:
            # Here we analyze each machine and classify it dependent on the 
            # protocol and type of communication
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


    def process_input(self):
        input_file = open(self.input_file)
        machines_json = json.load(input_file)
        for machine in machines_json:
            new_machine = Machine(**machine)
            self.machines.append(new_machine)
        

    def create_output(self):
        # We need to serialize the list of machine objects into something 
        # that is JSON serializable
        machines_json = []
        for machine in self.machines:
            machines_json.append(machine.__dict__)

        print(f'Writing Classified machines to: {self.output_file}')
        with open(self.output_file, 'w') as output_file:
            json.dump(machines_json, output_file, sort_keys=True, indent=4)
        

    def visualizer(self):
        net = Visualizer()
        net.add_machines(self.machines)
        net.show()

    def modbus_type(self, tcp_packet):
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