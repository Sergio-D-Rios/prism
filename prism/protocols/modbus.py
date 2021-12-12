from scapy.utils import RawPcapNgReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import scapy.contrib.modbus as mb

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


def modbus_sort(self):
    pass

def modbus_classify(self):
    pass