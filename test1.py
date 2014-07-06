import switchyard.lib.topo.topobuild as tbuild
import switchyard.lib.topo.util as tutil

t = tbuild.Topology()
h1 = t.addHost()
h2 = t.addHost()
s1 = t.addSwitch()
s2 = t.addSwitch()
print (t)
t.addLink(h1,s1,1000000,0.1)
t.addLink(h2,s2,1000000,0.1)
t.addLink(s1,s2,1000000,0.1)

tutil.save_to_file(t, 'xtopo.txt')
tutil.save_graph(t, 'xtopo.png')

