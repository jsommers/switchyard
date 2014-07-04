import switchyard.lib.topo.topobuild as tbuild
import switchyard.lib.topo.util as tutil
import switchyard.sys as syss
import sys

t = tutil.load_from_file('xtopo.txt')
# print ("low-level topology data: {}".format(t))

syss.run_simulation(t, 'myhub')
