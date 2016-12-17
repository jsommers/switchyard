from switchyard.lib.userlib import *

def main(net):
    # add some informational text about ports on this device
    log_info ("Hub is starting up with these ports:")
    for port in net.ports():
        log_info ("{}: ethernet address {}".format(port.name, port.ethaddr))

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except Shutdown:
            # got shutdown signal
            break
        except NoPackets:
            # try again...
            continue

        # send the packet out all ports *except*
        # the one on which it arrived
        for port in net.ports():
            if port.name != input_port:
                net.send_packet(port.name, packet)

    # shutdown is the last thing we should do
    net.shutdown()
