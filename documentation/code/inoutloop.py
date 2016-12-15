from switchyard.lib.userlib import *

def main(net):
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except Shutdown:
            log_info ("Got shutdown signal; exiting")
            break
        except NoPackets:
            log_info ("No packets were available.")
            continue

        # if we get here, we must have received a packet
        log_info ("Received {} on {}".format(packet, input_port))
        net.send_packet(input_port, packet)
