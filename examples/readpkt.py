#!/usr/bin/env python3
'''
Simple program that reads contents of a tcpdump tracefile
and prints packets to stdout.
'''

import sys
from switchyard.pcapffi import *
from switchyard.lib.packet import *

files = ['sydump.pcap']
if len(sys.argv) > 1:
    files = sys.argv[1:]

for infile in files:
    print("Opening {}.".format(infile))
    reader = PcapReader(infile)
    count = 0
    while True:
        pkt = reader.recv_packet()
        if pkt is None:
            break
        p = Packet(raw=pkt.raw)
        print (p)
        count += 1
    print ("Got {} packets from {}.".format(count, infile))
    reader.close()
