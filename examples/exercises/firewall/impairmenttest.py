#!/usr/bin/env python3

from copy import deepcopy
import random

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
permit tcp src any srcport any dst 172.16.42.0/24 dstport 80 ratelimit 12500
# rule 9
permit tcp src 192.168.0.0/16 srcport any dst any dstport 443
# rule 10
permit tcp src any srcport any dst 172.16.42.0/24 dstport 443

# permit, but impair certain traffic flows
# rule 11
permit tcp src 192.168.0.0/24 srcport any dst any dstport 8000 impair

# permit, but rate limit icmp to 100 bytes/sec
# rule 12
permit icmp src any dst any ratelimit 100

# block everything else
# rule 13
deny ip src any dst any 
'''

def firewall_tests():
    s = TestScenario("Firewall tests")
    s.add_file('firewall_rules.txt', firewall_rules)

    # two ethernet ports; no IP addresses assigned to
    # them.  eth0 is internal network-facing, and eth1
    # is external network-facing.
    s.add_interface('eth0', '00:00:00:00:0b:01')
    s.add_interface('eth1', '00:00:00:00:0b:02')

    t = TCP()
    t.ACK = 1
    t.ack = random.randrange(0,2**32)
    t.seq = random.randrange(0,2**32)
    t.src = random.randrange(2**12,2**16)
    t.dst = 8000
    ip = IPv4()
    ip.src = '192.168.0.13'
    ip.dst = IPv4Address(random.randrange(2**16, 2**32))
    ip.protocol = IPProtocol.TCP
    pkt = Ethernet() + ip + t + "This is some TCP data!".encode()
    # fill in any other packet headers or data to the constructed packet
    s.expect(PacketInputEvent('eth0',pkt), 
        'Packet that should be impaired arrives on eth0')

    # Modify the packet in the same way that you expect the firewall
    # to modify the packet.  
    pkt = deepcopy(pkt) # make a full copy of the packet before modifying

    s.expect(PacketOutputEvent('eth1',pkt),
        'Test description for a packet departure --- what should happen?')

    return s

scenario = firewall_tests()
