from switchyard.lib.userlib import *

scenario = TestScenario("packet forwarding example")

# three interfaces on this device
scenario.add_interface('eth0', 'ab:cd:ef:ab:cd:ef', '1.2.3.4', '255.255.0.0')
scenario.add_interface('eth1', '00:11:22:ab:cd:ef', '5.6.7.8', '255.255.0.0')
scenario.add_interface('eth2', 'ab:cd:ef:00:11:22', '9.10.11.12', '255.255.255.0')

# add a forwarding table file to be written out when the test 
# scenario is executed
scenario.add_file('forwarding_table.txt', '''
# network   subnet-mask   next-hop      port
2.0.0.0     255.0.0.0     9.10.11.13    eth2
3.0.0.0     255.255.0.0   5.6.100.200   eth1
''')


# construct a packet to be received
p = Ethernet(src="00:11:22:33:44:55", dst="66:55:44:33:22:11") + \
    IPv4(src="1.1.1.1", dst="2.2.2.2", protocol=IPProtocol.UDP, ttl=61) + \
    UDP(src=5555, dst=8888) + b'some payload'

# expect that the packet is received
scenario.expect(PacketInputEvent('eth0', p), 
    "A udp packet destined to 2.2.2.2 arrives on port eth0")

# and subsequently forwarded out the correct port; employ 
# subset (exact=False) matching, along with a check that the
# IPv4 TTL was decremented exactly by 1.
scenario.expect(PacketOutputEvent('eth2', p, exact=False, 
    predicate='''lambda pkt: pkt.has_header(IPv4) and pkt[IPv4].ttl == 60'''),
    "The udp packet destined to 2.2.2.2 should be forwarded out port eth2, with an appropriately decremented TTL.")
