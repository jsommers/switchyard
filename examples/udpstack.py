#!/usr/bin/env python3

from switchyard.lib.userlib import *

def main(net):
    intf = None
    for i in net.interfaces():
        if i.iftype == InterfaceType.Loopback:
            intf = i
            break
    if intf is None:
        raise Exception("This example is designed to use the loopback interface but I didn't find one")

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

    net.shutdown()

def handle_app_data(net, intf, appdata):
    flowaddr,message = appdata
    log_debug("Received data from app layer: <{}>".format(message))
    log_debug("flowaddr: {}".format(flowaddr))

    proto,srcip,srcport,dstip,dstport = flowaddr
    p = Null() + IPv4(protocol=proto, src=intf.ipaddr, dst=dstip, ipid=0xabcd, ttl=64, flags=IPFragmentFlag.DontFragment) + UDP(src=srcport,dst=dstport) + message

    log_debug("Sending {} to {}".format(p, intf.name))
    net.send_packet(intf, p)

def handle_network_data(netdata):
    timestamp, ingress, pkt = netdata
    log_debug("On {} received {}".format(ingress, pkt))
    if pkt.has_header(IPv4):
        ipidx = pkt.get_header_index(IPv4)
        ip = pkt[ipidx]
        if pkt[ipidx].protocol == IPProtocol.UDP:
            udp = pkt.get_header(UDP)
            ApplicationLayer.send_to_app(IPProtocol.UDP, (ip.dst, udp.dst),
            (ip.src, udp.src), pkt[-1].data)
        elif pkt[ipidx].protocol == IPProtocol.ICMP:
            log_info("Received ICMP message: {}".format(pkt[ipidx+1]))
        else:
            log_info("Received an unexpected packet: {}".format(pkt[1:]))
            
