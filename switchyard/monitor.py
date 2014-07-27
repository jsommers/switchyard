from importlib import import_module
from abc import ABCMeta,abstractmethod
import threading
import pdb
import queue

from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib import pcapffi
from switchyard.lib.importcode import import_user_code
from switchyard.switchyard.switchy import LLNetBase
from switchyard.switchyard.switchy_common import NoPackets,Shutdown
from switchyard.lib.topo.topobuild import Interface

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
    @abstractmethod
    def __call__(self, devname, now, packet):
        pass

    @abstractmethod
    def stop(self):
        pass

class NullMonitor(AbstractMonitor):
    def __init__(self, *args):
        pass

    def __call__(self, devname, now, packet):
        return

    def stop(self):
        pass

class PcapMonitor(AbstractMonitor):
    def __init__(self, node, intf, *args):
        outfile = ''
        if len(args) > 0:
            outfile = args[0]
        if not outfile.endswith('.pcap'):
            outfile = "{}_{}_{}.pcap".format(node,intf,outfile)
        self.dumper = pcapffi.PcapDumper(outfile)

    def __call__(self, devname, now, packet):
        self.dumper.write_packet(packet.to_bytes(), ts=now)

    def stop(self):
        self.dumper.close()

class InteractiveMonitor(AbstractMonitor):
    def __init__(self, node, intf, *args):
        self.pktlib = __import__('switchyard.lib.packet', fromlist=('packet',))
        self.__node = node
        self.__intf = intf

    def __call__(self, devname, now, packet):
        xlocals = {'packet':packet, 'pktlib':self.pktlib,'EthAddr':EthAddr,'IPAddr':IPAddr}
        debugstmt = '''
# Nonstatement to get into the debugger
'''
        pdb.Pdb.prompt = '{}:{} >'.format(self.__node, self.__intf)
        pdb.run(debugstmt, globals={}, locals=xlocals)

    def stop(self):
        pass

class CodeMonitor(AbstractMonitor):
    def __init__(self, node, intf, *args, **kwargs):
        module = args[0]
        self.__usercode = import_user_code(module)
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

    def __thread_entry(self):
        self.__usercode(self.__debugnet)
        

if __name__ == '__main__':
    pass
