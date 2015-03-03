'''
Simple tcpdump-like program that use Switchyard libraries for
reading packets from a local device and dumping them to a file.
'''

from switchyard.lib.pcapffi import *
from switchyard.lib.packet import *

reader = PcapLiveDevice('en0')
writer = PcapDumper("tcpdump.pcap")
print (reader)
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
