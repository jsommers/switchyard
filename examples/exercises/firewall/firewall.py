from switchyard.lib.userlib import *
import time

def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))

    while True:
        pkt = None
        try:
            timestamp,input_port,pkt = net.recv_packet(timeout=0.5)
        except NoPackets:
            pass
        except Shutdown:
            break

        if pkt is not None:

            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            net.send_packet(portpair[input_port], pkt)

            
    net.shutdown()
