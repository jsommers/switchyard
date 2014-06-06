import sys
from cn_toolbelt.lib.topo.util import load_from_file

__author__ = 'jsommers@colgate.edu'
__doc__ = 'SwitchYard Substrate Simulator'


'''
create separate threads for each node simulated?
create a Queue to represent a link between each node?

once created, throw user into a CLI where they can interact with the network
    ping from one host to another
    show the network (in some way)
        simple view and detailed view (with all addresses/interfaces)
    go onto fake console for any node?
    reload code on any node?

    i.e., it will sort of work like mininet :-/
'''

import threading
from Queue import Queue
import time

class X(object):
    pass

class NodeExecutor(object):
    def __init__(self, name, x):
        self.queues = {}
        self.name = name
        self.x = x

    def addLink(self, devname, queue, capacity, delay):
        print "{} add interface {} {} {}".format(self.name, devname, capacity, delay)
        self.queues[devname] = queue

    def run(self):
        while True:
            time.sleep(1.0)
            print "In node thread {}".format(self.name)


def run_simulation(topo, swycode):
    xnode = {}
    x = X()
    for n in topo.nodes:
        print n,topo.nodes[n].asDict()
        nexec = NodeExecutor(n, x, swycode)
        t = threading.Thread(target=nexec.run)
        xnode[n] = (t,nexec)
    for thisnode,edgedict in topo.links.iteritems():
        for nextnode,edgeinfo in edgedict.iteritems():
            q = Queue()
            thisnode_dev = edgeinfo[thisnode]
            nextnode_dev = edgeinfo[nextnode]
            cap = edgeinfo['capacity']
            delay = edgeinfo['delay']
            xnode[thisnode][1].addLink(thisnode_dev, q, cap, delay)
            xnode[nextnode][1].addLink(nextnode_dev, q, cap, delay)
    for n,xtup in xnode.iteritems():
        print n,xtup
        xtup[0].start()

def main():
    topofile = None
    swycode = None
    if len(sys.argv) > 1:
        topofile = sys.argv[1]
    if len(sys.argv) > 2:
        swycode = sys.argv[2]
    if not (topofile and swycode):
        print "Need topofile and swy code"
        sys.exit(-1)

    topo = load_from_file(topofile)
    run_simulation(topo, swycode)


if __name__ == '__main__':
    main()
