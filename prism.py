#!/usr/bin/env python3

###############################################################################
#####################  UnumScrape - Web Link Scraper ##########################
##########Created by Sergio Rios for Educational Purposes Only ################
###############################################################################

import argparse
from argparse import RawDescriptionHelpFormatter

#Helper/Description Strings for the project
manual_descriptions = {
    "proj_description": 'prism is an ICS Network Analysis tool that is meant to'
    'provide classification and awareness of network assets to users.',

    "pcap_file": 'Used to specify the input PCAP file prism will analyze.'
}

def argumentParser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=manual_descriptions['proj_description'],
        formatter_class=RawDescriptionHelpFormatter)

    parser.add_argument('pcap_file', type=str, action='store',
                        help=manual_descriptions['pcap_file'])

    return parser.parse_args()

def main():
    args = argumentParser()
    print("Testing")
    print(args.pcap_file)

    
if __name__ == '__main__':
    main()