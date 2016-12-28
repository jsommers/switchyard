from switchyard.lib.userlib import *

scenario = TestScenario("test example")
scenario.add_interface('eth0', 'ab:cd:ef:ab:cd:ef', '1.2.3.4', '255.255.0.0', iftype=InterfaceType.Wired)

scenario.expect(PacketInputEvent('eth1', Packet()), "A packet knocks on the door...")
