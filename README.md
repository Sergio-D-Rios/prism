# Prism
A Static ICS Network Analysis, Classification, and Visualization tool

# Installation
There are a few dependencies for Prism, they can all be installed by doing the 
following commands.
* `pip install scapy`
    * Note: there is currently an issue with the pip install version of Scapy that will give a packet error. Recommend doing the latest development install if issues are encountered. There is also a known scapy issue where it's imports may hang. The tool will still complete if you encounter this issue it will just take a lot longer.
* `pip install pyvis` 
    * Used for generating the resulting visualization

Any additional dependencies are visible in the *requirements.txt* file

# Usage
 To access Prism's manual simply run `python3 prism_launcher.py --help`

 To run Prism simply run `python3 prism_launcher.py` with any options desired, these are discussed in detail below.

 * `-pc,--pcap_file` used to specify the path to a pcap file to be analyzed. Both .pcap and .pcapng files are accepted.
 * `-pf, --protocol_filters` used to specify which ICS protocols to focus analysis on. Currently only the modbus module is fully functional
 * `-i, --input_file` An input file can be loaded into Prism in order to view a previously generated graph or have a custom machine JSON list loaded to the visualizer.
 * `-o, --output_file` Used to specify the name of a generated output file. This output file contains all of the machines classified in JSON.
 * `-v, --visualize` Used to generate an html visualization of the analyzed input or pcap file. 

 # Interpreting the visualization
 To run a visualization on test water plant data use the following
 
 * `python3 prism_launcher.py -pc water_plant.pcapng -pf modbus -v` 

 The generated visualization will have 4 machines represented by connected circles. The connections represent communications between machines. The colors of the circles represent their determined classification. 

 * Red 
    * Prism determined this machine is acting as some sort of alarm due to its repeated read behavior
* Blue
    * Prism determined this machine to be acting as some sort of PLC due to it responding to write and read queries
* Green
    * Prism determined this machine to be acting as some sort of HMI or engineering workstation due to its behavior interacting with PLC(s) on the network

One can hover over a specific node on the graph in order to receive a detailed view of the conversations the machine is having.