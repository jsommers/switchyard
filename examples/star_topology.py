from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.topo.util import *
from switchyard.lib.topo.topobuild import *

t = Topology(auto_macs=True,name="Example star topology")
t.addRouter('router')
for i in range(3):
    switchname = 'switch{}'.format(i+1)
    t.addSwitch(switchname)
    t.addLink('router', switchname, '10Mb/s', '100 msec')

    rif,swif = t.getLinkInterfaces('router', switchname)
    t.setInterfaceAddresses('router',rif,ip="192.168.{}.1".format(i+1),netmask="255.255.255.0")
    for j in range(3):
        hostname = 'host{}_{}'.format(i+1,j+1)
        t.addHost(hostname)
        t.addLink(switchname, hostname, '1Gb/s', '0.001')

        hif,swif = t.getLinkInterfaces(hostname, switchname)
        t.setInterfaceAddresses(hostname,hif,ip="192.168.{}.{}".format(i+1,j+1),netmask="255.255.255.0")

save_to_file(t, 'examples/star_topo.json')
