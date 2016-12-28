#!/usr/bin/env python3

from random import randint
from copy import deepcopy
import struct
import time

from switchyard.lib.userlib import *

firewall_rules = '''
# drop everything from an internal subnet which shouldn't be allowed
# to communicate with rest of internet
# rule 1
deny ip src 192.168.42.0/24 dst any 
# rule 2
deny ip src any dst 192.168.42.0/24 

# allow traffic to/from an internal web server that should
# be accessible to external hosts
# rule 3
permit tcp src 192.168.13.13 srcport 80 dst any dstport any
# rule 4
permit tcp src any srcport any dst 192.168.13.13 dstport 80

# allow DNS (udp port 53) traffic in/out of network
# rule 5
permit udp src 192.168.0.0/16 srcport any dst any dstport 53 
# rule 6
permit udp src any srcport 53 dst 192.168.0.0/16 dstport any 

# allow internal hosts access to web (tcp ports 80 and 443)
# rate limit http traffic to 100 kB/s (12500 bytes/sec), but
# don't rate limit any encrypted HTTP traffic.
# rule 7
permit tcp src 192.168.0.0/16 srcport any dst any dstport 80 ratelimit 12500
# rule 8
permit tcp src any srcport 80 dst 192.168.0.0/16 dstport any ratelimit 12500
# rule 9
permit tcp src 192.168.0.0/16 srcport any dst any dstport 443
# rule 10
permit tcp src any srcport 443 dst 192.168.0.0/16 dstport any

# permit, but impair certain traffic flows
# rule 11
permit tcp src 192.168.0.0/24 srcport any dst any dstport 8000 impair
# rule 12
permit tcp src any srcport 8000 dst 192.168.0.0/24 dstport any impair

# permit, but rate limit icmp to 150 bytes/sec.
# NB: this includes *both* directions!
# rule 13
permit icmp src any dst any ratelimit 150

# block everything else
# rule 14
deny ip src any dst any 
'''

def rand16(start=0):
    return randint(start,2**16-1)

def rand32(start=0):
    return randint(start, 2**32-1)

def rand8(start=0):
    return randint(start, 2**8-1)

def mketh(xtype = EtherType.IP):
    e = Ethernet()
    e.ethertype = xtype
    e.src = struct.pack('xxI',rand32())
    e.dst = struct.pack('xxI',rand32())
    return e

def swap(pkt):
    pkt = deepcopy(pkt)
    e = pkt.get_header(Ethernet)
    e.src,e.dst = e.dst,e.src
    ip = pkt.get_header(IPv4)
    ip.src,ip.dst = ip.dst, ip.src
    ip.ttl = 255-ip.ttl
    ip.ipid = 0
    tport = None
    if pkt.has_header(TCP):
        tport = pkt.get_header(TCP)
        tport.seq, tport.ack = tport.ack, tport.seq
        tport.ACK = 1
    elif pkt.has_header(UDP):
        tport = pkt.get_header(UDP)
    if tport is not None:
        tport.src,tport.dst = tport.dst, tport.src
    return pkt

def firewall_tests():
    s = TestScenario("Firewall tests")
    s.add_file('firewall_rules.txt', firewall_rules)

    # two ethernet ports; no IP addresses assigned to
    # them.  eth0 is internal network-facing, and eth1
    # is external network-facing.
    s.add_interface('eth0', '00:00:00:00:0b:01')
    s.add_interface('eth1', '00:00:00:00:0b:02')

    # first set of tests: check that packets that should be allowed through
    # are allowed through
    t = TCP() 
    t.SYN = 1
    t.src = 80
    t.dst = rand16(10000)
    t.seq = rand32()
    t.ack = rand32()
    t.window = rand16(8192)
    ip = IPv4()
    ip.src = '192.168.13.13'
    ip.dst = rand32()
    ip.ttl = rand8(12)     
    ip.protocol = IPProtocol.TCP
    pkt = mketh() + ip + t
    s.expect(PacketInputEvent('eth0',pkt), 
        'Packet arriving on eth0 should be permitted since it matches rule 3.')
    s.expect(PacketOutputEvent('eth1',pkt),
        'Packet forwarded out eth1; permitted since it matches rule 3.')
    s.expect(PacketInputEvent('eth1',swap(pkt)), 
        'Packet arriving on eth1 should be permitted since it matches rule 4.')
    s.expect(PacketOutputEvent('eth0',swap(pkt)),
        'Packet forwarded out eth0; permitted since it matches rule 3.')

    u = UDP()
    u.src = rand16(10000)
    u.dst = 53
    ip.src = int(IPv4Address('192.168.113.0')) | rand8()
    ip.dst = rand32()
    ip.ttl = rand8(16)
    ip.protocol = IPProtocol.UDP
    pkt = mketh() + ip + u
    s.expect(PacketInputEvent('eth0', pkt),
        'Packet arriving on eth0 should be permitted since it matches rule 5.')
    s.expect(PacketOutputEvent('eth1', pkt),
        'Packet forwarded out eth1; permitted since it matches rule 5.')
    s.expect(PacketInputEvent('eth1', swap(pkt)),
        'Packet arriving on eth1 should be permitted since it matches rule 6.')
    s.expect(PacketOutputEvent('eth0', swap(pkt)),
        'Packet forwarded out eth0; permitted since it matches rule 6.')

    t = TCP()
    t.src = rand16(10000)
    t.dst = 443
    t.seq = rand32()
    t.ack = rand32()
    t.SYN = 1
    ip.src = int(IPv4Address('192.168.113.0')) | rand8()
    ip.dst = rand32()
    ip.ttl = rand8(16)
    ip.protocol = IPProtocol.TCP
    pkt = mketh() + ip + t
    s.expect(PacketInputEvent('eth0', pkt),
        'Packet arriving on eth0 should be permitted since it matches rule 9.')
    s.expect(PacketOutputEvent('eth1', pkt),
        'Packet forwarded out eth1; permitted since it matches rule 9.')
    s.expect(PacketInputEvent('eth1', swap(pkt)),
        'Packet arriving on eth1 should be permitted since it matches rule 10.')
    s.expect(PacketOutputEvent('eth0', swap(pkt)),
        'Packet forwarded out eth0; permitted since it matches rule 10.')

    # let tokens build if they initialize buckets to 0
    time.sleep(1)

    # next few tests hit rules that have rate limits, but these should
    # all be allowed since the payloads are small enough.
    t = TCP()
    t.src = rand16(10000)
    t.dst = 80
    t.seq = rand32()
    t.ack = rand32()
    t.window = rand16()
    t.SYN = 1
    ip.src = int(IPv4Address('192.168.213.0')) | rand8()
    ip.dst = rand32()
    ip.ttl = rand8(16)
    ip.protocol = IPProtocol.TCP
    pkt = mketh() + ip + t
    s.expect(PacketInputEvent('eth0', pkt),
        'Packet arriving on eth0 should be permitted since it matches rule 7.')
    s.expect(PacketOutputEvent('eth1', pkt),
        'Packet forwarded out eth1; permitted since it matches rule 7.')
    s.expect(PacketInputEvent('eth1', swap(pkt)),
        'Packet arriving on eth1 should be permitted since it matches rule 8.')
    s.expect(PacketOutputEvent('eth0', swap(pkt)),
        'Packet forwarded out eth0; permitted since it matches rule 8.')

    ip.src = rand32()
    ip.dst = rand32()
    ip.protocol = IPProtocol.ICMP
    pkt = mketh() + ip + ICMP()
    s.expect(PacketInputEvent('eth0', pkt),
        'Packet arriving on eth0 should be permitted since it matches rule 12.')
    s.expect(PacketOutputEvent('eth1', pkt),
        'Packet forwarded out eth1; permitted since it matches rule 12.')
    s.expect(PacketInputEvent('eth1', swap(pkt)),
        'Packet arriving on eth1 should be permitted since it matches rule 12.')
    s.expect(PacketOutputEvent('eth0', swap(pkt)),
        'Packet forwarded out eth0; permitted since it matches rule 12.') 

    # second set of tests: check that packets should be blocked/denied
    # from explicit deny rules are not forwarded.
    t = TCP()
    t.src = rand16(10000)
    t.dst = 443
    t.seq = rand32()
    t.ack = rand32()
    t.window = rand16()
    t.ACK = 1
    t.PSH = 1
    ip.src = int(IPv4Address('192.168.42.0')) | rand8()
    ip.dst = rand32()
    ip.ttl = rand8(16)
    ip.protocol = IPProtocol.TCP
    pkt = mketh() + ip + t

    # shouldn't matter which interface one of these packets arrives on;
    # rule matching should be done regardless...
    s.expect(PacketInputEvent('eth0', pkt),
        'Packet arriving on eth0 should be blocked since it matches rule 1.')
    s.expect(PacketInputEvent('eth1', pkt),
        'Packet arriving on eth1 should be blocked since it matches rule 1.')
    s.expect(PacketInputEvent('eth0', swap(pkt)),
        'Packet arriving on eth0 should be blocked since it matches rule 2.')
    s.expect(PacketInputEvent('eth1', swap(pkt)),
        'Packet arriving on eth1 should be blocked since it matches rule 2.')

    # third set of tests: check that other IPv4 packets are blocked (rule 13),
    # but that other types of packets are allowed (i.e., non-IPv4)

    # UDP packet with source and dest IP addrs not in 192.168.0.0/16 
    # should implicitly be blocked.
    ip = IPv4()    
    ip.protocol = IPProtocol.UDP
    ip.src = rand32(2**24)
    ip.dst = rand32(2**24)
    udp = UDP()
    udp.src = rand16()
    udp.dst = rand16()
    pkt = mketh() + ip + udp + b'Hello, little UDP packet!'
    s.expect(PacketInputEvent('eth0', pkt),
        'UDP packet arrives on eth0; should be blocked since addresses it contains aren\'t explicitly allowed (rule 13).')
    s.expect(PacketInputEvent('eth1', pkt),
        'UDP packet arrives on eth1; should be blocked since addresses it contains aren\'t explicitly allowed (rule 13).')

    # ARP should be blocked
    pkt = create_ip_arp_request(mketh().src, rand32(), rand32())
    s.expect(PacketInputEvent('eth0', pkt),
        'ARP request arrives on eth0; should be allowed since it does not match any rule')
    s.expect(PacketOutputEvent('eth1', pkt),
        'ARP request should be forwarded out eth1 since it does not match any rule')
    s.expect(PacketInputEvent('eth1', pkt),
        'ARP request arrives on eth1; should be blocked since it is not explicitly allowed (rule 13).')
    s.expect(PacketOutputEvent('eth0', pkt),
        'ARP request should be forwarded out eth0 since it does not match any rule')

    # IPv6 should be blocked
    e = mketh()
    e.ethertype = EtherType.IPv6
    ip = IPv6()
    ip.nextheader = IPProtocol.ICMPv6
    pkt = e + ip + ICMPv6()
    s.expect(PacketInputEvent('eth0', pkt),
        'IPv6 packet arrives on eth0; should be allowed since it does not match any rule.')
    s.expect(PacketOutputEvent('eth1', pkt),
        'IPv6 packet forwarded out eth1 since it does not match any rule.')
    s.expect(PacketInputEvent('eth1', pkt),
        'IPv6 packet arrives on eth1; should be blocked since it is not explicitly allowed (rule 13).')
    s.expect(PacketOutputEvent('eth0', pkt),
        'IPv6 packet forwarded out eth0 since it does not match any rule.')

    return s

scenario = firewall_tests()
