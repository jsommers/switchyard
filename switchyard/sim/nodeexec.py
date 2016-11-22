import sys
import heapq
from collections import namedtuple, defaultdict
import threading
from queue import Queue,Empty
import time
from importlib import import_module
from cmd import Cmd
import re
from abc import ABCMeta,abstractmethod

from ..llnetbase import LLNetBase
from ..lib.exceptions import NoPackets,Shutdown
from ..lib.logging import log_debug
from .monitor import *
from ..lib.topo import *
from .linkem import LinkEmulator


EgressPipe = namedtuple('EgressPipe', ['queue','delay','capacity','remote_devname'])
class NodeExecutor(LLNetBase):
    __slots__ = ['__done', '__ingress_queue', '__egress_pipes', '__name','__interfaces','__symod', '__linkem', '__tolinkem','__recv_monitors','__t']
    def __init__(self, name, ingress_queue, symod=None):
        LLNetBase.__init__(self)
        self.__ingress_queue = ingress_queue
        self.__egress_pipes = {}
        self.__name = name
        self.__interfaces = {}
        self.__symod = symod
        self.__done = False
        self.__linkem = None
        self.__tolinkem = None
        self.__recv_monitors = {'host': NullMonitor()}
        self.__t = None

    def sendHostPacket(self, pkt):
        self.__ingress_queue.put( ('host', pkt) )

    def addEgressInterface(self, devname, intf, queue, capacity, delay, remote_devname):
        # print ("Adding egress interface on {} {}".format(self.name, devname))
        self.__egress_pipes[devname] = EgressPipe(queue, delay, capacity, remote_devname)
        self.__interfaces[devname] = intf
        self.__recv_monitors[devname] = NullMonitor()

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

    def attach_recv_monitor(self, interface, monitorobject):
        self.__recv_monitors[interface] = monitorobject

    def remove_recv_monitor(self, interface):
        self.__recv_monitors[interface] = NullMonitor()

    def recv_packet(self, timeout=0.0, timestamp=False):
        #
        # FIXME: not sure about how best to handle...
        #
        giveup_time = time.time() + timeout
        inner_timeout = 0.05
         
        while timeout == 0.0 or time.time() < giveup_time:
            try:
                devname,packet = self.__ingress_queue.get(block=True, timeout=inner_timeout)
                now = time.time()
                self.__recv_monitors[devname](devname,now,packet)
                if timestamp:
                    return devname,now,packet
                return devname,packet
            except Empty:
                pass

            if self.__done:
                raise Shutdown()

        raise NoPackets()

    def send_packet(self, dev, packet):
        egress_pipe = self.__egress_pipes[dev]
        now = time.time()
        delay = now + len(packet) / float(egress_pipe.capacity) + egress_pipe.delay
        self.__tolinkem.put( (delay, (egress_pipe.remote_devname, packet), egress_pipe.queue) )

    def shutdown(self):
        self.__linkem.shutdown()
        self.__done = True
        log_debug("Joining node codeexec thread {} node {}".format(self.__t.name, self.__name))
        self.__t.join()

    def __idleloop(self):
        while not self.__done:
            try:
                devname,ts,packet = self.recv_packet(timestamp=True, timeout=0.1)
            except Shutdown:
                break
            except NoPackets:
                pass

    def run(self):
        self.__tolinkem = Queue()
        self.__linkem = LinkEmulator(self.__tolinkem)
        self.__t = threading.Thread(target=self.__linkem.run)
        self.__t.start()
        self.startcode()

    def resetcode(self, mod=None):
        self.__symod = mod
        self.startcode()

    def startcode(self):
        if self.__symod:
            self.__symod(self)
        else:
            self.__idleloop()
        self.__t.join()
        del self.__t
        del self.__linkem
        del self.__tolinkem 
        del self.__egress_pipes
        del self.__recv_monitors

