from switchyard.lib.userlib import *

scenario = TestScenario("in/out test scenario example")

# only one interface on this imaginary device
scenario.add_interface('eth0', 'ab:cd:ef:ab:cd:ef', '1.2.3.4', '255.255.0.0', 
    iftype=InterfaceType.Wired)

# construct a packet to be received
p = Ethernet(src="00:11:22:33:44:55", dst="66:55:44:33:22:11") + \
    IPv4(src="1.1.1.1", dst="2.2.2.2", protocol=IPProtocol.UDP) + \
    UDP(src=5555, dst=8888) + b'some payload'

# expect that the packet is received
scenario.expect(PacketInputEvent('eth0', p), 
    "A udp packet should arrive on eth0")

# and expect that the packet is sent right back out
scenario.expect(PacketOutputEvent('eth0', p, exact=True), 
    "The udp packet should be emitted back out eth0")
