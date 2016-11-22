from importlib import import_module
from abc import ABCMeta,abstractmethod
import threading
import pdb
import queue

from ..lib.packet import *
from ..lib.address import EthAddr, IPAddr
from .. import pcapffi
from ..importcode import import_or_die
from ..llnetbase import LLNetBase
from ..lib.exceptions import NoPackets, Shutdown
from ..lib.topo.topobuild import Interface

class MonitorManager(object):
    _monitors = []
    _queue = queue.Queue()

    def __init__(self):
        raise Exception("Don't instantiate me.")

    @staticmethod
    def add_monitor(monitor):
        MonitorManager._monitors.append(monitor)

    @staticmethod
    def reset():
        for mon in MonitorManager._monitors:
            mon.stop()
        del MonitorManager._monitors
        del MonitorManager._queue
        MonitorManager._monitors = []
        MonitorManager._queue = queue.Queue()

    @staticmethod
    def add_to_debug_queue(node, interface, packet):
        barrier = threading.Barrier(2)
        MonitorManager._queue.put( (node,interface,packet,barrier) )
        barrier.wait()

    @staticmethod
    def get_from_debug_queue():
        try:
            return MonitorManager._queue.get(block=False)
        except queue.Empty:
            return None

class DebugInspector(LLNetBase):
    def __init__(self, node, intf, queue):
        self.__interfaces = {intf.name: intf}
        self.__done = False
        self.__queue = queue
        self.__name = node

    def name(self):
        return self.__name

    def interfaces(self):
        return self.__interfaces.values()

    def ports(self):
        return self.interfaces()

    def recv_packet(self, timeout=0.0, timestamp=False):
        if self.__done:
            raise Shutdown()

        try:
            timeout = max(1.0, timeout)
            rv = self.__queue.get(timeout=timeout)
            if rv[0] is None:
                raise NoPackets()
            if timestamp:
                return rv
            else:
                return rv[0],rv[2]
        except queue.Empty:
            raise NoPackets()

    def send_packet(self, dev, packet):
        print ("Packets cannot be sent with a debug monitor")

    def shutdown(self):
        self.__done = True

class AbstractMonitor(metaclass=ABCMeta):
    def __init__(self, *args):
        MonitorManager.add_monitor(self)

    @abstractmethod
    def __call__(self, devname, now, packet):
        pass

    @abstractmethod
    def stop(self):
        pass

class NullMonitor(AbstractMonitor):
    def __init__(self, *args):
        super().__init__(args)

    def __call__(self, devname, now, packet):
        return

    def stop(self):
        pass

class PcapMonitor(AbstractMonitor):
    def __init__(self, node, intf, *args):
        super().__init__(args)
        outfile = ''
        if len(args) > 0:
            outfile = args[0]
        if not outfile.endswith('.pcap'):
            if outfile:
                outfile = "{}_{}_{}.pcap".format(node,intf,outfile)
            else:
                outfile = "{}_{}.pcap".format(node,intf)
        self.dumper = pcapffi.PcapDumper(outfile)

    def __call__(self, devname, now, packet):
        self.dumper.write_packet(packet.to_bytes(), ts=now)

    def stop(self):
        self.dumper.close()

class InteractiveMonitor(AbstractMonitor):
    def __init__(self, node, intf, *args):
        super().__init__(args)
        self.__node = node
        self.__intf = intf

    def __call__(self, devname, now, packet):
        MonitorManager.add_to_debug_queue(self.__node, devname, packet)

    @staticmethod
    def exec(node, intf, packet, barrier):
        pktlib = __import__('switchyard.lib.packet', fromlist=('packet',))
        xlocals = {'packet':packet, 'pktlib':pktlib,'EthAddr':EthAddr,'IPAddr':IPAddr}
        print ("Debugging packet object on receive at {}:{}".format(node, intf))
        debugstmt = '''
# Nonstatement to get into the debugger
'''
        pdb.run(debugstmt, globals={}, locals=xlocals)
        barrier.wait()

    def stop(self):
        pass

class CodeMonitor(AbstractMonitor):
    def __init__(self, node, intf, *args, **kwargs):
        super().__init__(args)
        module = args[0]
        self.__usercode = import_or_die(module)
        self.__thread = threading.Thread(target=self.__thread_entry)
        self.__queue = queue.Queue()
        self.__debugnet = DebugInspector(node, Interface(intf,None,None), self.__queue)
        self.__thread.start()

    def __call__(self, devname, now, packet):
        self.__queue.put((devname,now,packet))

    def stop(self):
        self.__queue.put( (None,None,None) )
        self.__debugnet.shutdown()
        self.__thread.join()
        del self.__thread
        del self.__queue

    def __thread_entry(self):
        log_debug("Code monitor thread start {}".format(threading.current_thread().ident))
        self.__usercode(self.__debugnet)
        log_debug("Code monitor thread end {}".format(threading.current_thread().ident))

if __name__ == '__main__':
    pass
