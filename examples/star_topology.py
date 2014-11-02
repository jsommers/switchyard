from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.topo.util import *
from switchyard.lib.topo.topobuild import *

t = Topology()
t.addRouter('router')
for i in range(3):
    switchname = 'switch{}'.format(i+1)
    t.addSwitch(switchname)
    t.addLink('router', switchname, '10Mb/s', '100 msec')
    for j in range(3):
        hostname = 'host{}_{}'.format(i+1,j+1)
        t.addHost(hostname)
        t.addLink(switchname, hostname, '1Gb/s', '0.001')

#        h1ifname,r1ifname = t.getLinkInterfaces('h1','r1')
#        t.setInterfaceAddresses('h1',h1ifname,ip="10.0.1.1",netmask="255.255.0.0",mac="11:22:33:44:55:66") 

save_to_file(t, 'examples/star_topo.json')
