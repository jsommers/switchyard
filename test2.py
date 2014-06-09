import cn_toolbelt.lib.topo.topobuild as tbuild
import cn_toolbelt.lib.topo.util as tutil
import cn_toolbelt.sys as syss
import sys

t = tutil.load_from_file('xtopo.txt')
print "low-level topology data:",t

syss.run_simulation(t, 'myhub')
