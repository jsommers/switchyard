#!/usr/bin/python

import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange, custom, quietRun, dumpNetConnections
from mininet.cli import CLI

from time import sleep, time
from subprocess import Popen, PIPE
import subprocess
import argparse
import os

parser = argparse.ArgumentParser(description="Mininet portion of pyrouter")
# no arguments needed as yet :-)
args = parser.parse_args()
lg.setLogLevel('info')

class PyRouterTopo(Topo):

    def __init__(self, args):
        # Add default members to class.
        super(PyRouterTopo, self).__init__()

        # Host and link configuration
        #
        #  external----firewall----internal
        #
        # external refers to the internet outside a given
        # enterprise's network.  internal refers to the
        # enterprise's network.

        self.addHost('external')
        self.addHost('internal')
        self.addHost('firewall')
        
        for node in ['internal','external']:
            self.addLink(node, 'firewall', bw=1000, delay="10ms")

def set_ip_pair(net, node1, node2, ip1, ip2):
    node1 = net.get(node1)
    ilist = node1.connectionsTo(net.get(node2)) # returns list of tuples
    intf = ilist[0]
    intf[0].setIP(ip1)
    intf[1].setIP(ip2)

def set_ip(net, node, ifname, addr):
    node_object = net.get(node)
    intf = node_object.intf(ifname)
    intf.setIP(addr)

def reset_macs(net, node, macbase):
    ifnum = 1
    node_object = net.get(node)
    for intf in node_object.intfList():
        if node not in str(intf):
            continue # don't set lo or other interfaces
        node_object.setMAC(macbase.format(ifnum), intf)
        ifnum += 1

    for intf in node_object.intfList():
        print node,intf,node_object.MAC(intf)

def set_def_route(net, fromnode, gw):
    node_object = net.get(fromnode)
    node_object.cmdPrint("route add default gw {}".format(gw))

def setup_addressing(net):
    reset_macs(net, 'internal', '00:00:00:00:01:{:02x}')
    reset_macs(net, 'external', '00:00:00:00:10:{:02x}')
    reset_macs(net, 'firewall', '00:00:00:00:0b:{:02x}')

    set_ip(net,'internal','internal-eth0','192.168.0.1/24')
    set_ip(net,'external','external-eth0','192.168.0.2/24')

def stop_nodegrams(net):
    for nname in ['external','internal','firewall']:
        n = net.get(nname)
        n.cmd("killall python3")

def main():
    topo = PyRouterTopo(args)
    net = Mininet(topo=topo, link=TCLink, cleanup=True, autoSetMacs=True, controller=None)
    setup_addressing(net)
    net.staticArp()
    net.interact()

if __name__ == '__main__':
    main()
