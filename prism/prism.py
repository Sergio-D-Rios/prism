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
        if 'modbus' in self.protocol_filters:
            # FIXME: figure out why there is two sets of machines being sorted
            self.machines.extend(modbus_sort(self.packets, self.machines))
        elif 's7comm' in self.protocol_filters:
            print('s7comm not yet supported')
            exit()
        elif 'cip' in self.protocol_filters:
            print('cip not yet supported')
            exit()
        elif 'bacnet' in self.protocol_filters:
            print('bacnet not yet supported')
            exit()


    def pcap_classifier(self):
        if 'modbus' in self.protocol_filters:
            # print(self.machines)
            self.machines.extend(modbus_classify(self.machines))
        elif 's7comm' in self.protocol_filters:
            print('s7comm not yet supported')
            exit()
        elif 'cip' in self.protocol_filters:
            print('cip not yet supported')
            exit()
        elif 'bacnet' in self.protocol_filters:
            print('bacnet not yet supported')
            exit()        


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

        print(f'Writing machines to: {self.output_file}')
        with open(self.output_file, 'w') as output_file:
            json.dump(machines_json, output_file, sort_keys=True, indent=4)
        

    def visualizer(self):
        net = Visualizer()
        net.add_machines(self.machines)
        net.show()
