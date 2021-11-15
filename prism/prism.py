from scapy.utils import RawPcapNgReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import os
import sys

class Prism():

    def __init__(self, 
                 pcap_file: str="", 
                 protocol_filter: list=['modbus'], 
                 output_file: str="",
                 visualize: bool=False):
        self.pcap_file = pcap_file
        self.protocol_filter = protocol_filter
        self.output_file = output_file
        self.visualize_flag = visualize
        self.machines = {}
        self.packet_list = []

    def launch(self):
        if self.pcap_file == "":
            print("No pcap file loaded, please relaunch with appropriate file")

        self.pcap_filter()
        self.pcap_sorter()
        self.pcap_classifier()

        if not self.output_file == "":
            self.create_output()
        
        if self.visualize_flag:
            self.visualizer()

    def pcap_filter(self):
        print("")

    def pcap_sorter(self):
        print("")

    def pcap_classifier(self):
        # Start processing the passed in pcap
        for (packet_data, packet_metadata) in RawPcapNgReader(self.pcap_file):

            # Create the ethernet header for processed packet
            ethernet_packet = Ether(packet_data)

            print("Ethernet")
            print(dir(ethernet_packet))

            ip_packet = ethernet_packet[IP]

            print("IP")
            print(dir(ip_packet))

            tcp_packet = ip_packet[TCP]

            print("TCP")
            print(dir(tcp_packet))

            # Eventually we need to add a protocol filter on the pcap here

            # Now that we have the filtered packets, we can start building objects
            # based on IPs

            # First we need to check to see if this IP has been used before

            # Possible pickling for performance upgrade later on

            exit(0)

    def create_output(self):
        print("")

    def visualizer(self):
        print("")
