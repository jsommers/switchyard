from switchyard.lib.userlib import *

def main(net):
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet(timeout=1.0)
        except NoPackets:
            # timeout waiting for packet arrival
            continue
        except Shutdown:
            # we're done; bail out of while loop
            break

        # invoke the debugger every time we get here, which
        # should be for every packet we receive!
        debugger()
        hdrs = packet.num_headers()

    # before exiting our main function,
    # perform shutdown on network
    net.shutdown()
