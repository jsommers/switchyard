import socket
import ssl
from threading import Thread
import time
from heapq import heappush, heappop, heapreplace

from switchyard.lib.packet import *
from switchyard.lib.openflow import *
from switchyard.lib.address import *
from switchyard.lib.common import *


class PacketBufferManager(object):

    def __init__(self, buffsize):
        self._buffsize = buffsize


class TableEntry(object):

    def __init__(self, matcher):
        self._match = matcher
        self._cookie = 0
        self._idle_timeout = self._hard_timeout = 0
        self._actions = []
        self._priority = 0

    @property
    def priority(self):
        return self._priority

    def __cmp__(self, other):
        return cmp(self.priority, other.priority)

    def __hash__(self):
        return self._cookie


class OpenflowSwitch(object):
    '''
    An Openflow v1.0 switch.
    '''

    def __init__(self, switchyard_net, switchid):
        self._switchid = switchid  # aka, dpid
        self._controller_connections = []
        self._switchyard_net = switchyard_net
        self._running = True
        self._buffer_manager = PacketBufferManager(100)
        self._xid = 0
        self._miss_len = 1500
        self._flags = OpenflowConfigFlags.FragNormal
        self._ready = False
        self._table = []

    def add_controller(self, host, port):
        print("Switch connecting to controller {}:{}".format(host, port))
        sock = socket.socket()  # ssl.wrap_socket(socket.socket())
        sock.settimeout(1.0)
        sock.connect((host, port))
        t = Thread(target=self._controller_thread, args=(sock,))
        self._controller_connections.append(t)
        t.start()

    @property
    def xid(self):
        self._xid += 1
        return self._xid

    def _controller_thread(self, sock):
        def _hello_handler(pkt):
            print("Hello version: {}".format(pkt[0].version))
            self._ready = True

        def _features_request_handler(pkt):
            header = OpenflowHeader(OpenflowType.FeaturesReply, self.xid)
            featuresreply = OpenflowSwitchFeaturesReply()
            featuresreply.dpid_low48 = self._switchid
            for i, intf in enumerate(self._switchyard_net.ports()):
                featuresreply.ports.append(
                    OpenflowPhysicalPort(i, intf.ethaddr, intf.name))
            print("Sending features reply: {}".format(featuresreply))
            send_openflow_message(sock, header + featuresreply)

        def _set_config_handler(pkt):
            setconfig = pkt[1]
            self._flags = setconfig.flags
            self._miss_len = setconfig.miss_send_len
            print("Set config: flags {} misslen {}".format(
                self._flags, self._miss_len))

        def _get_config_request_handler(pkt):
            print("Get Config request")
            header = OpenflowHeader(OpenflowType.GetConfigReply, self.xid)
            reply = OpenflowGetConfigReply()
            reply.flags = self._flags
            reply.miss_send_len = self._miss_len
            send_openflow_message(sock, header + reply)

        def _flow_mod_handler(pkt):
            print("Flow mod")
            fmod = pkt[1]
            if fmod.command == FlowModCommand.Add:
                print ("Add")
            elif fmod.command == FlowModCommand.Modify:
                print ("Modify")
            elif fmod.command == FlowModCommand.ModifyStrict:
                print ("ModStrict")
            elif fmod.command == FlowModCommand.Delete:
                print ("Delete")
            elif fmod.command == FlowModCommand.DeleteStrict:
                print ("DeleteStrict")
            else:
                raise Exception("Unknown flowmod command {}".format(fmod.command))

        def _barrier_request_handler(pkt):
            print("Barrier request")
            reply = OpenflowHeader(OpenflowType.BarrierReply, xid=header.xid)
            send_openflow_message(sock, reply)

        _handler_map = {
            OpenflowType.Hello: _hello_handler,
            OpenflowType.FeaturesRequest: _features_request_handler,
            OpenflowType.SetConfig: _set_config_handler,
            OpenflowType.GetConfigRequest: _get_config_request_handler,
            OpenflowType.FlowMod: _flow_mod_handler,
            OpenflowType.BarrierRequest: _barrier_request_handler,
        }

        def _unknown_type_handler(pkt):
            print("Unknown OF message type: {}".format(pkt[0].type))

        pkt = Packet()
        pkt += OpenflowHeader(OpenflowType.Hello, self.xid)
        send_openflow_message(sock, pkt)

        while self._running:
            try:
                pkt = receive_openflow_message(sock)
            except socket.timeout:
                continue

            if pkt is not None:
                header = pkt[0]
                _handler_map.get(header.type, _unknown_type_handler)(pkt)

    def datapath_loop(self):
        print("datapath loop: not ready to receive")
        while not self._ready:
            time.sleep(0.5)

        print("datapath loop: READY to receive")
        while True:
            try:
                port, packet = self._switchyard_net.recv_packet(timeout=1.0)
            except Shutdown:
                break
            except NoPackets:
                continue

            log_info("Packet arrived: {}->{}".format(port, packet))

            # FIXME: process incoming packet on data plane

    def shutdown(self):
        self._running = False
        for t in self._controller_connections:
            t.join()


def main(net, host='localhost', port=6633, switchid=EthAddr("de:ad:00:00:be:ef")):
    switch = OpenflowSwitch(net, switchid)
    switch.add_controller('localhost', 6633)
    switch.datapath_loop()
    switch.shutdown()
    net.shutdown()
