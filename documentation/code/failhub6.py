from switchyard.lib.userlib import *

def main(net):
    timestamp,input_port,packet = net.recv_packet()
    print ("Received {} on {}".format(packet, input_port))
    packet[Ethernet].src = "ba:aa:aa:ba:aa:aa"
    net.send_packet("eth0", packet)
