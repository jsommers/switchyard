from switchyard.lib.userlib import *

class ProtocolStack(object):
    def __init__(self, net):
        self._net = net

    def handle_app_data(self, appdata):
        # do something to handle application data here, likely
        # resulting in an eventual call to self._net.send_packet()

    def handle_network_data(self, netdata):
        # do something with network data here, likely resulting
        # in an eventual call to ApplicationLayer.send_to_app()

    def main_loop(self):
        while True:
            appdata = None
            try:
                appdata = ApplicationLayer.recv_from_app(timeout=0.1)
            except NoPackets:
                pass
            except Shutdown:
                break
            if appdata is not None:
                handle_app_data(net, intf, appdata)

            netdata = None
            try:
                netdata = net.recv_packet(timeout=0.1)
            except NoPackets:
                pass
            except Shutdown:
                break
            if netdata is not None:
                handle_network_data(netdata)


def main(net):
    stack = ProtocolStack(net)
    stack.main_loop()
    net.shutdown()
