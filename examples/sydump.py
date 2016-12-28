#!/usr/bin/env python3
'''
Simple tcpdump-like program that use Switchyard libraries for
reading packets from a local device and dumping them to a file.
'''

import sys
from switchyard.pcapffi import *
from switchyard.lib.packet import *

interface = 'en0'
if len(sys.argv) > 1:
    interface = sys.argv[1]

reader = PcapLiveDevice(interface)
writer = PcapDumper("sydump.pcap")
print("Reading from {}".format(interface))
count = 0
while True:
    pkt = reader.recv_packet(10.0)
    if pkt is None:
        break
    try:
        p = Packet(raw=pkt.raw)
        print (p)
    except Exception as e:
        print ("Failed to parse packet: {}".format(e))

    writer.write_packet(pkt.raw)
    count += 1

print ("Got {} packets".format(count))
reader.close()
writer.close()
