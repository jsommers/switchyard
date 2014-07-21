import sys
import heapq
from collections import namedtuple
import threading
from queue import Queue,Empty
import time
from importlib import import_module
from cmd import Cmd
import re

from switchyard.switchyard.switchy import LLNetBase
from switchyard.switchyard.switchy_common import NoPackets,Shutdown
from switchyard.lib.topo import *
from switchyard.lib.packet import *
from switchyard.lib.textcolor import *


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
        self.prompt = '{}switchyard>{} '.format(TextColor.CYAN,TextColor.RESET)
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
            print ("Not enough arguments to show ('help show' for more info)")
            return

        if 'links'.startswith(cmdargs[0]):
            self.__show_links(cmdargs[1:])
        elif 'nodes'.startswith(cmdargs[0]):
            self.__show_nodes(cmdargs[1:])
        elif 'topology'.startswith(cmdargs[0]):
            self.__show_topology(cmdargs[1:])
        elif '?' == cmdargs[0]:
            self.help_show() 
        else:
            print ("Invalid show subcommand {}".format(cmdargs[0]))

    def do_set(self, line):
        argerr = "Not enough arguments to set ('help set' for more info)"
        cmdargs = line.split()
        if len(cmdargs) < 5:
            print (argerr)
            return

        if 'node'.startswith(cmdargs[0]):
            nodename = cmdargs[1]
            interface = cmdargs[2]
            ethaddr = None
            ipaddr = None
            netmask = None
            if 'ethernet'.startswith(cmdargs[3]):
                ethaddr = cmdargs[4]
            elif 'inet'.startswith(cmdargs[3]):
                ipaddr = cmdargs[4]
                netmask = ''
                if len(cmdargs) > 5:
                    if 'netmask'.startswith(cmdargs[5]):
                        if len(cmdargs) > 6:
                            netmask = cmdargs[6]
                        else:
                            print ("Missing netmask value")
                            return
                    elif len(cmdargs) == 6:
                        netmask = cmdargs[5]
                    else:
                        print ("Unrecognized configuration parameter")
                        return
                try:
                    self.topology.setInterfaceAddresses(nodename, interface, mac=ethaddr, ip=ipaddr, netmask=netmask)
                except Exception as e:
                    print ("Error setting addresses: {}".format(str(e)))
            else:
                print ("Invalid address family: must be ethernet or inet")
                return

        elif 'link'.startswith(cmdargs[0]):
            n1,n2 = cmdargs[1:3]
            bw = delay = ''
            cmdargs = cmdargs[3:]
            print ("Remaining cmd args: ",cmdargs)
            if len(cmdargs) < 2 or len(cmdargs) % 2 != 0:
                print ("Wrong number of arguments to 'set link'")
                return
            for i in range(0,len(cmdargs),2):
                if cmdargs[i] == 'bw' or 'bandwidth'.startswith(cmdargs[i]) or 'capacity'.startswith(cmdargs[i]):
                    bw = cmdargs[i+1]
                elif 'delay'.startswith(cmdargs[i]):
                    delay = cmdargs[i+1]
                else:
                    print ("Unrecognized link parameter {}".format(cmdargs[i]))
                    return
            for n in (n1,n2):
                if n not in self.topology:
                    print ("Node {} doesn't exist.".format(n))
                    return
            if not self.topology.hasLink(n1,n2):
                print ("No link exists between {} and {}".format(n1,n2))
                return
            print ("change link {} {} bw {} delay {}".format(n1,n2,bw,delay))
            print ("Link: ",self.topology.getLink(n1,n2))
        else:
            print ("Invalid set command: must start with 'set node' or 'set link'")

        # set node s0 eth0 ether ethaddr
        # set node s0 eth0 inet ipaddr netmask netmask
        # set link s0 s1 bw X
        # set link s0 s1 delay X

    def do_save(self, line):
        print ("save commands not implemented yet")
        # save topology <filename>

    def do_load(self, line):
        print ("load command not implemented yet")

    def do_add(self, line):
        print ("add commands not implemented yet")
        # add <host/switch/router> <name>
        # add link node0 node1 bw X delay X

    def do_monitor(self, line):
        print ("monitor commands not implemented yet")
        # monitor link X Y [filename]
        # monitor node X [filename]
        # -- should allow adding simple tcpdump monitor, as well as
        # adding code that gets a callback when packets arrive (but
        # doesn't allow sending)

        # show monitor
        # show monitor link X Y

    def __show_nodes(self, cmdargs):
        if len(cmdargs) == 0:
            print (' '.join(self.topology.nodes))
        else:
            if cmdargs[0] in self.topology.nodes:
                nobj = self.topology.getNode(cmdargs[0])
                nodeifs = nobj['nodeobj'].interfaces
                plural = 's'
                if len(nodeifs) == 1: plural = ''
                print ("Node {} is a {} and has {} interface{}:".format(cmdargs[0], nobj['type'], len(nodeifs), plural))
                for ifname,intf in sorted(nodeifs.items()):
                    print ("\t{}".format(intf))
            else:
                print ("Node {} does not exist.".format(cmdargs[0]))

    def __printlink(self, u, v, ldict):
        print ('{} <-> {} ({})'.format(u,v,ldict['label']))

    def __show_links(self, cmdargs):
        if len(cmdargs) == 0:
            # show all links
            for u,v in self.topology.links:
                linkdict = self.topology.getLink(u,v)
                self.__printlink(u,v,linkdict)
        else:
            if cmdargs[0] in self.topology.nodes: 
                # show links related to a given node
                for u,v in self.topology.edges_from(cmdargs[0]):
                    linkdict = self.topology.getLink(u,v)
                    self.__printlink(u,v,linkdict)
            else:
                print ("Can't show links for unknown node {}".format(cmdargs[0]))

    def __show_topology(self, cmdargs):
        print ("Close window in order to proceed")
        showaddrs = showintfs = False
        for arg in cmdargs:
            if arg.startswith('addr'):
                showaddrs = True
                showintfs = True
            elif arg.startswith('int'):
                showintfs = True
        show_graph(self.topology, showaddrs=showaddrs, showintfs=showintfs)

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
        show (nodes|node <nodename>)
        show (links|link <nodename>)
        show topology 
        ''')

    def help_set(self):
        print ('''
        set node <nodename> <ifacename> ethernet <ethaddr>
        set node <nodename> <ifacename> inet <ipaddr> [netmask <mask>]
        set node <nodename> <ifacename> inet <ipaddr>/<prefixlen>
        ''')

    def help_exit(self):
        print ("Really?  You need help for the exit command?")

    def help_EOF(self):
        self.help_exit()

    def help_sendeth(self):
        print ("Flood a simple raw Ethernet packet from a node")


def run_simulation(topo, swycode):
    '''
    Get the simulation substrate started.  The key things are to set up
    a series of queues that connect nodes together and get the link emulation
    objects started (all inside the NodeExecutor class).  The NodePlumbing
    named tuples hold together threads for each node, the emulation
    substrate (NodeExecutors), and the ingress queue that each node receives
    packets from.
    '''
    xnode = {}
    exec_module = import_module(swycode)

    ingress_queues = {}

    for n in topo.nodes:
        ingress_queues[n] = q = Queue()
        nexec = NodeExecutor(n, q, exec_module)
        t = threading.Thread(target=nexec.run)
        xnode[n] = NodePlumbing(t,nexec,q)

    for u,v in topo.links:
        linkdict = topo.getLink(u,v)
        nearnode = xnode[u]
        farnode = xnode[v]
        udev = linkdict[u]
        vdev = linkdict[v]
        cap = linkdict['capacity']
        delay = linkdict['delay']
        egress_queue = farnode.queue
        intf = topo.getNode(u)['nodeobj'].getInterface(udev)
        nearnode.nexec.addEgressInterface(udev, intf, egress_queue, cap, delay, vdev)

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
