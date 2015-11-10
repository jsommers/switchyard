import sys
from queue import Queue, Empty
from threading import Thread, Lock
from socket import timeout, AddressFamily, AF_INET, SOCK_DGRAM, SOCK_STREAM, IPPROTO_TCP, IPPROTO_UDP
from socket import error as sockerr
from subprocess import getoutput
import re
import random
from textwrap import indent

from switchyard.lib.hostfirewall import Firewall
from switchyard.lib.pcapffi import PcapLiveDevice
from switchyard.lib.common import NoPackets, log_debug, log_info, setup_logging, red, yellow
from switchyard.lib.packet import IPProtocol

def _gather_ports():
    portset = set()
    out = getoutput("netstat -an | grep ^udp")
    for x in out.split('\n'):
        fields = x.split()
        if len(fields) < 5:
            continue
        ports = fields[3].strip()
        # print (ports)
        mobj = re.search('[\.:](\d+|\*)$', ports)
        if mobj:
            port = (mobj.groups()[0])
            if port != '*':
                portset.add(int(port))
    return portset

def _get_ephemeral_port():
    ports = _gather_ports()
    while True:
        p = random.randint(30000,60000)
        if p not in ports:
            return p

def port_in_use(p):
    ports = _gather_ports()
    return p in ports

_app_layer_lock = Lock()

class ApplicationLayer(object):
    _init = False
    _to_app = None
    _from_app = None

    def __init__(self):
        raise RuntimeError("Don't init me.")

    @staticmethod
    def init():
        with _app_layer_lock:
            if ApplicationLayer._init:
                return
            ApplicationLayer._init = True
            ApplicationLayer._to_app = Queue()
            ApplicationLayer._from_app = Queue()

    @staticmethod
    def recv_from_app(timeout=1.0):
        try:
            data,local_addr,remote_addr = ApplicationLayer._from_app.get(timeout=timeout)
            return data,local_addr,remote_addr
        except Empty:
            pass
        raise NoPackets()

    @staticmethod
    def send_to_app(data, source_addr, dest_addr):
        ApplicationLayer._to_app.put( (data,source_addr,dest_addr) )

    @staticmethod
    def queues():
        return ApplicationLayer._from_app, ApplicationLayer._to_app


def setup_switchyard_stack(proto, localaddr):
    log_debug("Starting up stack thread")
    ApplicationLayer.init()
    return ApplicationLayer.queues()



# need to import lots of stuff out of base socket module so that we can avoid
# completely reinventing the wheel here

class socket(object):
    __slots__ = ('_family','_socktype','_protoname','_proto','_timeout','_block','_remote_addr','_local_addr', '_socket_queue_to_stack','_socket_queue_from_stack')
    def __init__(self, family, xtype, proto=0, fileno=0):
        family = AddressFamily(family)
        if family != AddressFamily.AF_INET:
            raise NotImplementedError("socket for family {} not implemented".format(family))
        if xtype not in [SOCK_DGRAM, SOCK_STREAM]:
            raise NotImplementedError("socket type {} not implemented".format(xtype))
        self._family = family
        self._socktype = xtype
        self._protoname = 'udp'
        self._proto = IPProtocol.UDP
        if self._socktype == SOCK_STREAM:
            self._protoname = 'tcp'
            self._proto = IPProtocol.TCP
        self._timeout = None
        self._block = True
        self._remote_addr = (None,None)
        self._local_addr = ('0.0.0.0',_get_ephemeral_port())

        log_debug("Adding firewall/bpf rule {} dst port {}".format(self._protoname, self._local_addr[1]))
        try:
            Firewall.add_rule("{}:{}".format(self._protoname, self._local_addr[1]))
            # only get packets with destination port of local port, or any
            # icmp packets
            PcapLiveDevice.set_bpf_filter_on_all_devices("{} dst port {} or icmp".format(self._protoname, self._local_addr[1]))
        except: 
            with yellow():
                print ("Unable to complete socket emulation setup (failed on firewall/bpf filter installation).  Did you start the program via srpy?")
                import traceback
            print ("Here is the raw exception information:")
            with red():
                print(indent(traceback.format_exc(), '    '))
            sys.exit()

        ApplicationLayer.init()
        self._socket_queue_to_stack, self._socket_queue_from_stack = ApplicationLayer.queues()

    @property
    def family(self):
        return self._family

    @property
    def type(self):
        return self._proto

    @property
    def proto(self):
        return self._proto

    def __del__(self):
        log_debug("Exiting socket code")

    def accept(self):
        # block until we receive a TCP SYN, return a new socket object
        pass

    def close(self):
        # join the queue?
        pass

    def bind(self, address):
        # block firewall port
        # set stack to only allow packets through for addr/port
        self._local_addr = address
        # update firewall and pcap filters
        log_debug("Updating firewall/bpf rule on bind(): {} dst port {}".format(self._protoname, self._local_addr[1]))
        Firewall.add_rule("{}:{}".format(self._protoname, self._local_addr[1]))
        PcapLiveDevice.set_bpf_filter_on_all_devices("{} dst port {}".format(self._protoname, self._local_addr[1]))

    def connect(self, address):
        self._remote_addr = address
        pass

    def connect_ex(self, address):
        # ??
        pass

    def getpeername(self):
        # ??
        pass

    def getsockname(self):
        # ??
        pass

    def getsocktopt(self, option, buffersize=0):
        # ??
        pass

    def gettimeout(self):
        return self._timeout

    def listen(self, backlog):
        # null op?
        pass

    def recv(self, buffersize, flags=0):
        data,source,dest = self._recv(buffersize)
        return data

    def recv_into(self, *args):
        raise NotImplementedError("*_into calls aren't implemented")

    def recvfrom(self, buffersize, flags=0):
        data,source,dest = self._recv(buffersize)
        return data,source

    def recvfrom_into(self, *args):
        raise NotImplementedError("*_into calls aren't implemented")

    def _recv(self, nbytes):
        try:
            data,sourceaddr,destaddr = self._socket_queue_from_stack.get(block=self._block, timeout=self._timeout)
            log_debug("recv from {}<-{}:{}".format(data,sourceaddr,destaddr))
            return data,sourceaddr,destaddr
        except Empty as e:
            pass
        log_debug("recv timed out")
        raise timeout("timed out")

    def send(self, data, flags):
        self._send(data, self._remote_addr)

    def sendto(self, data, arg2, arg3=None):
        addr = arg3
        if arg3 is None:
            addr = arg2
        self._send(data, addr)

    def _send(self, data, remote_addr):
        log_debug("socketemu send: {}->{}:{}".format(data, self._local_addr, remote_addr))
        self._socket_queue_to_stack.put( (data, self._local_addr, remote_addr) )

    def sendall(self, data, flags):
        raise NotImplementedError("sendall isn't implemented")

    def sendmsg(self, *args):
        raise NotImplementedError("*msg calls aren't implemented")

    def recvmsg(self, *args):
        raise NotImplementedError("*msg calls aren't implemented")

    def setblocking(self, flags):
        self._block = bool(flags)

    def setsockopt(self, level, option, value):
        pass

    def settimeout(self, timeout):
        self._timeout = float(timeout)

    def shutdown(self, flag):
        pass

