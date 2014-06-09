import sys
import heapq
from collections import namedtuple
import threading
from Queue import Queue,Empty
import time
from importlib import import_module

from cn_toolbelt.switchyard.switchy import LLNetBase
from cn_toolbelt.switchyard.switchy_common import NoPackets
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

EgressPipe = namedtuple('EgressPipe', ['queue','delay','capacity','remote_devname'])

class Sim(object):
    def __init__(self):
        self.now = 0
        self.eventqueue = []

    def setend(self, endtime):
        self.endtime = endtime

    def after(self, delay, fn, *args):
        ts = self.now + delay
        heapq.heappush(self.eventqueue, (ts, fn, args))

    def run(self):
        while len(self.eventqueue):
            xtime, fn, args = heapq.heappop(self.eventqueue)
            self.now = xtime
            # print "Calling:",self.now, fn, args
            fn(*args)
            if self.now >= self.endtime:
                break

class NodeExecutor(LLNetBase):
    __slots__ = ['__ingress_queue', '__simulator', '__egress_pipes', 'name','__interfaces','__symod']
    def __init__(self, name, ingress_queue, symod):
        LLNetBase.__init__(self)
        self.__ingress_queue = ingress_queue
        self.__egress_pipes = {}
        self.__name = name
        self.__interfaces = {}
        self.__symod = symod
        self.__simulator = Sim()

    def addEgressInterface(self, devname, intf, queue, capacity, delay, remote_devname):
        print "{} add interface {} {} {}".format(self.__name, devname, capacity, delay)
        self.__egress_pipes[devname] = EgressPipe(queue, delay, capacity, remote_devname)
        print "adding egr interface",type(intf)
        self.__interfaces[devname] = intf

    def interfaces(self):
        return self.__interfaces.values()

    def set_devupdown_callback(self, callback):
        pass

    def interface_by_name(self, name):
        return self.__interfaces[name]

    def interface_by_ipaddr(self, ipaddr):
        pass

    def interface_by_macaddr(self, macaddr):
        pass

    def recv_packet(self, timeout=0.0, timestamp=False):
        try:
            devname,packet = self.__ingress_queue.get(block=True, timeout=timeout)
            if timestamp:
                return devname,time.time(),packet
            return devname,packet
        except Empty:
            raise NoPackets()

    def send_packet(self, dev, packet):
        egress_pipe = self.__egress_pipes[dev]
        delay = len(packet) / float(egress_pipe.capacity) + egress_pipe.delay
        self.__simulator.after(delay, self.__pipe_emit, egress_pipe.queue, (egress_pipe.remote_devname, packet) )

    def __pipe_emit(self, queue, data):
        queue.put(data)

    def shutdown(self):
        pass

    def run(self):
        for dev,ifx in self.__interfaces.iteritems():
            print self.__name,dev,str(ifx)

        print "In node thread {}".format(self.__name)
        self.__symod.switchy_main(self)


NodePlumbing = namedtuple('NodePlumbing', ['thread','nexec','queue'])

def cli(nodeinfo):
    while True:
        pass

def run_simulation(topo, swycode):
    print topo.nodes
    xnode = {}
    exec_module = import_module(swycode)

    ingress_queues = {}

    for n in topo.nodes:
        ingress_queues[n] = q = Queue()
        nexec = NodeExecutor(n, q, exec_module)
        t = threading.Thread(target=nexec.run)
        xnode[n] = NodePlumbing(t,nexec,q)

    for nearnodename,edgedict in topo.links.iteritems():
        for farnodename,edgeinfo in edgedict.iteritems():
            nearnode = xnode[nearnodename]
            farnode = xnode[farnodename]

            nearnode_dev = edgeinfo[nearnodename]
            farnode_dev = edgeinfo[farnodename]
            cap = edgeinfo['capacity']
            delay = edgeinfo['delay']
            egress_queue = farnode.queue
            intf =  topo.nodes[nearnodename].getInterface(nearnode_dev)

            nearnode.nexec.addEgressInterface(nearnode_dev, intf, egress_queue, cap, delay, farnode_dev)

    for nodename,plumbing in xnode.iteritems():
        plumbing.thread.start()

    cli(xnode)


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
