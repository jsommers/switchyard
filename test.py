import cn_toolbelt.lib.topo.topobuild as tbuild
import cn_toolbelt.lib.topo.util as tutil
import matplotlib.pyplot as plt
import networkx as nx

t = tbuild.Topology()
t.addNode()
t.addNode()
t.addNode()
t.addLink('a','b',1000000,0.1)
t.addLink('b','c',1000000,0.1)

tutil.save_to_file(t, 'xtopo.txt')
tutil.show_graph(t)
tutil.save_graph(t, 'xtopo.png')

