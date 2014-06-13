import sys
import heapq
from collections import namedtuple
import threading
from queue import Queue,Empty
import time
from importlib import import_module
from cmd import Cmd

from cn_toolbelt.switchyard.switchy import LLNetBase
from cn_toolbelt.switchyard.switchy_common import NoPackets,Shutdown
from cn_toolbelt.lib.topo.util import load_from_file,show_graph
from cn_toolbelt.lib.packet import Ethernet


__author__ = 'jsommers@colgate.edu'
__doc__ = 'SwitchYard Substrate Simulator'

EgressPipe = namedtuple('EgressPipe', ['queue','delay','capacity','remote_devname'])


class LinkEmulator(object):
    def __init__(self, inqueue):
        self.expiryheap = []
        self.inqueue = inqueue
        self.__shutdown = False

    def shutdown(self):
        self.__shutdown = True

    def run(self):
        while not self.__shutdown:

            now = time.time()
            while len(self.expiryheap) and self.expiryheap[0][0] <= now:
                expiretime,item,outqueue = heapq.heappop(self.expiryheap)
                outqueue.put(item)

            if len(self.expiryheap):
                expiretime,item,outqueue = self.expiryheap[0]
                timeout = expiretime - time.time()
            else:
                timeout = 1.0

            try:
                expiretime,item,outqueue = self.inqueue.get(timeout=timeout)
            except Empty:
                pass
            else:
                heapq.heappush(self.expiryheap, (expiretime, item, outqueue))


class NodeExecutor(LLNetBase):
    __slots__ = ['__done', '__ingress_queue', '__egress_pipes', '__name','__interfaces','__symod', '__linkem', '__tolinkem']
    def __init__(self, name, ingress_queue, symod):
        LLNetBase.__init__(self)
        self.__ingress_queue = ingress_queue
        self.__egress_pipes = {}
        self.__name = name
        self.__interfaces = {}
        self.__symod = symod
        self.__done = False
        self.__linkem = None
        self.__tolinkem = None

    def addEgressInterface(self, devname, intf, queue, capacity, delay, remote_devname):
        self.__egress_pipes[devname] = EgressPipe(queue, delay, capacity, remote_devname)
        self.__interfaces[devname] = intf

    @property
    def name(self):
        return self.__name

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
        #
        # FIXME: not sure about how best to handle...
        #
        giveup_time = time.time() + timeout
        inner_timeout = 0.1
         
        while timeout == 0.0 or time.time() < giveup_time:
            try:
                devname,packet = self.__ingress_queue.get(block=True, timeout=inner_timeout)
                if timestamp:
                    return devname,time.time(),packet
                return devname,packet
            except Empty:
                pass

            if self.__done:
                raise Shutdown()

        raise NoPackets()

    def send_packet(self, dev, packet):
        egress_pipe = self.__egress_pipes[dev]
        delay = time.time() + len(packet) / float(egress_pipe.capacity) + egress_pipe.delay
        self.__tolinkem.put( (delay, (egress_pipe.remote_devname, packet), egress_pipe.queue) )

    def shutdown(self):
        self.__linkem.shutdown()
        self.__done = True

    def run(self):
        self.__tolinkem = Queue()
        self.__linkem = LinkEmulator(self.__tolinkem)
        t = threading.Thread(target=self.__linkem.run)
        t.start()
        self.__symod.switchy_main(self)

NodePlumbing = namedtuple('NodePlumbing', ['thread','nexec','queue'])

class Cli(Cmd):
    def __init__(self, nodedata, topology):
        self.nodedata = nodedata
        self.topology = topology
        Cmd.__init__(self)
        self.prompt = 'sy> '
        self.doc_header = '''
FIXME: this is the documentation header.
'''

        try:
            import readline
        except ImportError:
            pass
        else:
            readline.clear_history()

    def emptyline(self):
        pass

    def precmd(self, line):
        return line

    def postcmd(self, stop, line):
        return stop

    def do_nodes(self, line):
        print (' '.join(self.nodedata.keys()))

    def do_links(self, line):
        print ("Not implemented")

    def do_topology(self, line):
        print ("Close window in order to proceed")
        show_graph(self.topology)

    def do_sendeth(self, line):
        sourcenode = line.strip()
        if sourcenode not in self.nodedata:
            print ("Invalid node name")
        else:
            e = Ethernet()
            e.src = '00:00:00:00:00:01'
            e.dst = '11:00:00:11:00:11'
            print ("Emitting {} on lo interface to {}".format(e, sourcenode))
            self.nodedata[sourcenode].queue.put(('lo',e))

    def do_EOF(self, line):
        print ("Got EOF")
        return self.do_exit(line)

    def do_exit(self, line):
        for np in self.nodedata.values():
            np.nexec.shutdown()
        return True

    def default(self, line):
        print ("Unrecognized command '{}'".format(line))

    def help_nodes(self):
        print ("Print a list of nodes in the network")

    def help_links(self):
        print ("Print a list of links in the network")

    def help_topology(self):
        print ("Show a graph of the network topology")

    def help_exit(self):
        print ("Really?  You need help for the exit command?")

    def help_EOF(self):
        self.help_exit()

    def help_sendeth(self):
        print ("Flood a simple raw Ethernet packet from a node")


def run_simulation(topo, swycode):
    # print topo.nodes
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

    cli = Cli(xnode, topo)
    cli.cmdloop()


def main():
    topofile = None
    swycode = None
    if len(sys.argv) > 1:
        topofile = sys.argv[1]
    if len(sys.argv) > 2:
        swycode = sys.argv[2]
    if not (topofile and swycode):
        print ("Need topofile and swy code")
        sys.exit(-1)

    topo = load_from_file(topofile)
    run_simulation(topo, swycode)


if __name__ == '__main__':
    main()
