from switchyard.lib.userlib import *

def main(net):
    timestamp,input_port,packet = net.recv_packet()
    print ("Received {} on {}".format(packet, input_port))
    del packet[-1]
    net.send_packet("eth0", packet)
