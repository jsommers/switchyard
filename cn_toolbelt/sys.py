import sys
import heapq
from collections import namedtuple
import threading
from queue import Queue,Empty
import time
from importlib import import_module
from cmd import Cmd
import re

from cn_toolbelt.switchyard.switchy import LLNetBase
from cn_toolbelt.switchyard.switchy_common import NoPackets,Shutdown
from cn_toolbelt.lib.topo.util import load_from_file,show_graph
from cn_toolbelt.lib.packet import *


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

    def do_show(self, line):
        cmdargs = line.split()
        if len(cmdargs) < 1:
            print ("Not enough arguments to show")
            return

        if 'link'.startswith(cmdargs[0]):
            self.__show_links(cmdargs[1:])
        elif 'node'.startswith(cmdargs[0]):
            self.__show_nodes(cmdargs[1:])
        elif 'topology'.startswith(cmdargs[0]):
            self.__show_topology(cmdargs[1:])
        else:
            print ("Invalid show subcommand {}".format(cmdargs[0]))

    def do_set(self, line):
        print ("set commands not implemented yet")

    def __show_nodes(self, cmdargs):
        if len(cmdargs) == 0:
            # show all node names
            print (' '.join(self.nodedata.keys()))
        else:
            if cmdargs[0] in self.nodedata.keys():
                xnode = self.topology.nodes[cmdargs[0]]
                print ("Node {} is a {} and has these interfaces:".format(cmdargs[0], xnode.nodetype))
                for intf in xnode.interfaces.values():
                    print ("\t{}".format(intf))
            else:
                print ("Node {} does not exist.".format(cmdargs[0]))

    def __printlink(self, ldict):
        nodes = []
        delay = capacity = 0.0
        for key,value in ldict.items():
            if key == 'delay':
                delay = value
            elif key == 'capacity':
                capacity = value
            else:
                nodes.append(':'.join([key,value]))
        print (' <-> '.join(nodes), end='')
        print ('; delay={} capacity={}'.format(delay, capacity))

    def __show_links(self, cmdargs):
        if len(cmdargs) == 0:
            # show all links
            xlinks = set()
            for nearnode,nearlinks in self.topology.links.items():
                for farnode, linkinfo in nearlinks.items():
                    if (nearnode,farnode) in xlinks or (farnode,nearnode) in xlinks:
                        continue
                    xlinks.add( (nearnode,farnode) )
                    xlinks.add( (farnode,nearnode) )
                    ltup = self.__printlink(linkinfo)
        else:
            if cmdargs[0] in self.topology.links: 
                # show links related to a given node
                for farnode,linkinfo in self.topology.links[cmdargs[0]].items():
                    self.__printlink(linkinfo)
            else:
                print ("Can't show links for unknown node {}".format(cmdargs[0]))

    def __show_topology(self, cmdargs):
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
        '''
        Implement short-cut commands: any unique command prefix should
        work.'''
        cmdargs = line.split()
        if re.match('^sh', cmdargs[0]):
            self.do_show(' '.join(cmdargs[1:]))
        elif re.match('^set', cmdargs[0]):
            self.do_sendeth(' '.join(cmdargs[1:]))
        elif re.match('^set', cmdargs[0]):
            self.do_set(' '.join(cmdargs[1:]))
        else:
            print ("Unrecognized command '{}'".format(line))

    def help_show(self):
        print ('''
        show (nodes|links|topology)
        ''')

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

    for nearnodename,edgedict in topo.links.items():
        for farnodename,edgeinfo in edgedict.items():
            nearnode = xnode[nearnodename]
            farnode = xnode[farnodename]

            nearnode_dev = edgeinfo[nearnodename]
            farnode_dev = edgeinfo[farnodename]
            cap = edgeinfo['capacity']
            delay = edgeinfo['delay']
            egress_queue = farnode.queue
            intf =  topo.nodes[nearnodename].getInterface(nearnode_dev)

            nearnode.nexec.addEgressInterface(nearnode_dev, intf, egress_queue, cap, delay, farnode_dev)

    for nodename,plumbing in xnode.items():
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
