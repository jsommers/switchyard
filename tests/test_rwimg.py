import os
from switchyard.lib.topo import *

t = Topology()
h1 = t.addHost()
h2 = t.addHost()
s1 = t.addSwitch()
s2 = t.addSwitch()
t.addLink(h1,s1,1000000,0.1)
t.addLink(h2,s2,1000000,0.1)
t.addLink(s1,s2,1000000,"1 microsec")

save_to_file(t, 'xtopo.txt')
save_graph(t, 'xtopo.png', showaddrs=False, showintfs=True)

os.unlink('xtopo.txt')
os.unlink('xtopo.png')
