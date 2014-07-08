from switchyard.lib.topo import *
import switchyard.sys as syss
import sys

t = load_from_file('xtopo.txt')
print ("low-level topology data: {}".format(t))

syss.run_simulation(t, 'myhub')
