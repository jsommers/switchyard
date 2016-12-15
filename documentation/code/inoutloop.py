from switchyard.lib.userlib import *

def main(net):
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except Shutdown:
            print ("Got shutdown signal; exiting")
            break
        except NoPackets:
            print ("No packets were available.")
            continue

        # if we get here, we must have received a packet
        print ("Received {} on {}".format(packet, input_port))
        net.send_packet(input_port, packet)
