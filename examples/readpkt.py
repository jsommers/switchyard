'''
Simple program that reads contents of a tcpdump tracefile
and prints packets to stdout.
'''


from switchyard.lib.pcapffi import *
from switchyard.lib.packet import *

reader = PcapReader('tcpdump.pcap')
print (reader)
count = 0
while True:
    pkt = reader.recv_packet()
    if pkt is None:
        break
    p = Packet(raw=pkt.raw)
    print (p)
    count += 1
print ("Got {} packets".format(count))
reader.close()
