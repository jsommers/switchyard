#!/usr/bin/env python

import sys
import asyncore
import socket
from threading import Thread
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import *
from switchyard.lib.openflow import *


def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP

    ippkt = IPv4()
    ippkt.srcip = IPAddr(ipsrc)
    ippkt.dstip = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = 32

    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def ofswitch_tests():
    s = Scenario("Openflow Switch Tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt("30:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", "172.16.42.2", "255.255.255.255")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet), "The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")

    return s


class FakeControllerHandler(asyncore.dispatcher):
    def __init__(self, *args, **kwargs):
        asyncore.dispatcher.__init__(self, *args, **kwargs)
        self._inited = False
        self._xid = 1000

    def handle_read(self):
        pkt = receive_openflow_message(self)
        print ("Got OF message: {}".format(pkt))
        if not self._inited:
            self._hello()
            self._features_request()
            self._inited = True

    @property
    def xid(self):
        x = self._xid
        self._xid += 1
        return x

    def _hello(self):
        pkt = Packet()
        pkt += OpenflowHeader(OpenflowType.Hello, self.xid)
        send_openflow_message(self, pkt)

    def _features_request(self):
        pkt = Packet()
        pkt += OpenflowHeader(OpenflowType.FeaturesRequest, self.xid)
        send_openflow_message(self, pkt)


class FakeControllerMaster(asyncore.dispatcher):
    def __init__(self, *args, **kwargs):
        asyncore.dispatcher.__init__(self, *args, **kwargs)
        print ("In master init")
        self.create_socket()
        self.set_reuse_addr()
        self.bind(("0.0.0.0", 6633))
        self.listen(5)

    def handle_accepted(self, sock, addr):
        print ("Controller got connection from switch at {}:{}".format(addr[0], addr[1]))
        global handler
        handler = FakeControllerHandler(sock)


def ofcontroller_thread():
    ## do this in a thread.
    print ("Starting fake ofcontroller")
    global master
    master = FakeControllerMaster()
    asyncore.loop(timeout=10)

def setup_ofcontroller():
    print ("Setting up controller")
    global controller
    controller.start()

def stop_ofcontroller():
    print ("Tearing down controller")
    global controller
    global master
    global handler
    handler.close()
    master.close()
    controller.join()
    
controller = Thread(target=ofcontroller_thread)
master = None
handler = None

scenario = ofswitch_tests()
scenario.setup = setup_ofcontroller
scenario.teardown = stop_ofcontroller
