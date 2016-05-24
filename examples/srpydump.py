'''
Simple tcpdump-like program that use Switchyard libraries for
reading packets from a local device and dumping them to a file.
'''

from switchyard.lib.packet import *
from switchyard.lib.common import *

def main(net):
    count = 0
    while True:
        try:
            input_port,tstamp,packet = net.recv_packet(timestamp=True,timeout=0.5)
        except Shutdown:
            # got shutdown signal
            break
        except NoPackets:
            # try again...
            continue

        print("{:.3f}: {} {}".format(tstamp,input_port,packet))
        count += 1

    print ("Got {} packets".format(count))
    net.shutdown()
