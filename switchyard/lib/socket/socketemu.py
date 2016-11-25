import sys
from queue import Queue, Empty
from subprocess import getoutput
import re
import random
from textwrap import indent
from copy import copy
from collections import namedtuple
import socket
from socket import error as sockerr
import importlib

# carefully control what we export to user code; we provide our own
# implementation for some symbols, and others simply aren't supported
explist = copy(socket.__all__)
dontimport = ('setdefaulttimeout', 'getdefaulttimeout', 'has_ipv6', 
    'socket', 'socketpair', 'fromfd', 'dup', 'create_connection')
for name in dontimport:
    explist.remove(name)
__all__ = explist
from socket import *

from ...hostfirewall import Firewall
from ...pcapffi import PcapLiveDevice
from ..exceptions import NoPackets
from ..logging import log_debug, log_info, log_warn, setup_logging, red, yellow
from ..packet import IPProtocol

has_ipv6 = True

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

ApplicationLayerData = namedtuple('ApplicationLayerData', 
    ['timestamp', 'flowaddr', 'message'])

_default_timeout = 1.0

def getdefaulttimeout():
    return _default_timeout

def setdefaulttimeout(tmo):
    global _default_timeout
    _default_timeout = tmo

class ApplicationLayer(object):
    _init = False
    _to_app = None
    _from_app = None

    def __init__(self):
        raise RuntimeError("Ouch.  Please don't try to create an instance "
                           "of {}.  Use the static init() method "
                           "instead.".format(self.__class__.__name__))
    @staticmethod
    def init():
        log_debug("Initializing application layer")
        if ApplicationLayer._init:
            return
        ApplicationLayer._init = True
        ApplicationLayer._to_app = {}
        ApplicationLayer._from_app = Queue()

    @staticmethod
    def recv_from_app(timeout=_default_timeout):
        try:
            data,local_addr,remote_addr = \
                ApplicationLayer._from_app.get(timeout=timeout)
            return data,local_addr,remote_addr
        except Empty:
            pass
        raise NoPackets()

    @staticmethod
    def send_to_app(data, source_addr, dest_addr):
        ApplicationLayer._to_app.put( (data,source_addr,dest_addr) )

    @staticmethod
    def register_socket(s):
        sock_queue = Queue()
        ApplicationLayer._to_app[s._sockid()] = sock_queue
        return ApplicationLayer._from_app, sock_queue

    @staticmethod
    def registry_update(s, oldid):
        sock_queue = ApplicationLayer._to_app.pop(oldid)
        ApplicationLayer._to_app[s._sockid()] = sock_queue

    @staticmethod
    def unregister_socket(s):
        sock_queue = ApplicationLayer._to_app.pop(s._sockid())
        if not sock_queue.empty():
            log_warn("Socket being destroyed still has data enqueued for application layer.")


class socket(object):
    __slots__ =  ('_family','_socktype','_protoname','_proto',
        '_timeout','_block','_remote_addr','_local_addr',
        '_socket_queue_to_stack','_socket_queue_from_stack')

    def __init__(self, family, xtype, proto=0, fileno=0):
        log_debug("In socket __init__")
        family = AddressFamily(family)
        if family not in (AddressFamily.AF_INET, AddressFamily.AF_INET6):
            raise NotImplementedError(
                "socket for family {} not implemented".format(family))
        if xtype not in (SOCK_DGRAM, SOCK_STREAM):
            raise NotImplementedError(
                "socket type {} not implemented".format(xtype))
        self._family = family
        self._socktype = xtype
        self._protoname = 'udp'
        self._proto = IPProtocol.UDP
        if self._socktype == SOCK_STREAM:
            self._protoname = 'tcp'
            self._proto = IPProtocol.TCP
        if proto != 0:
            self._proto = proto
        self._timeout = _default_timeout
        self._block = True
        self._remote_addr = (None,None)
        self._local_addr = ('0.0.0.0',_get_ephemeral_port())
        self.__set_fw_rules() 
        self._socket_queue_to_stack, self._socket_queue_from_stack = \
            ApplicationLayer.register_socket(self)

    def __set_fw_rules(self):
        log_debug("Adding firewall/bpf rule {} dst port {}".format(
            self._protoname, self._local_addr[1]))
        try:
            Firewall.add_rule("{}:{}".format(self._protoname,
                self._local_addr[1]))
            # only get packets with destination port of local port, or any
            # icmp packets
            PcapLiveDevice.set_bpf_filter_on_all_devices(
                "{} dst port {} or icmp or icmp6".format(self._protoname,
                                                self._local_addr[1]))
        except:
            with yellow():
                print ("Unable to complete socket emulation setup (failed on "
                       "firewall/bpf filter installation).  Did you start the "
                       " program via switchyard?")
                import traceback
            print ("Here is the raw exception information:")
            with red():
                print(indent(traceback.format_exc(), '    '))
            sys.exit()

    @property
    def family(self):
        return self._family

    @property
    def type(self):
        return self._socktype

    @property
    def proto(self):
        return self._proto

    def _sockid(self):
        return (self._family, self._proto, *self._local_addr)

    def _flowaddr(self):
        return (self._proto, *self._local_addr, *self._remote_addr) 

    def __del__(self):
        log_debug("Exiting socket code")

    def accept(self):
        # block until we receive a TCP SYN, return a new socket object
        pass

    def close(self):
        ApplicationLayer.unregister_socket(self)

    def bind(self, address):
        oldid = self._sockid()
        # block firewall port
        # set stack to only allow packets through for addr/port
        self._local_addr = address
        # update firewall and pcap filters
        self.__set_fw_rules()
        ApplicationLayer.registry_update(self, oldid)

    def connect(self, address):
        self._remote_addr = address
        pass

    def connect_ex(self, address):
        # ??
        pass

    def getpeername(self):
        return self._remote_addr

    def getsockname(self):
        return self._local_addr

    def getsocktopt(self, option, buffersize=0):
        raise NotImplementedError("set/get sockopt calls aren't implemented")

    def gettimeout(self):
        return self._timeout

    def listen(self, backlog):
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
            data,sourceaddr,destaddr = self._socket_queue_from_stack.get(
                block=self._block, timeout=self._timeout)
            log_debug("recv from {}<-{}:{}".format(data,sourceaddr,destaddr))
            return data,sourceaddr,destaddr
        except Empty as e:
            pass
        log_debug("recv timed out")
        raise timeout("timed out")

    def send(self, data, flags):
        self._send(data, self._flowaddr())

    def sendto(self, data, arg2, arg3=None):
        addr = arg3
        if arg3 is None:
            addr = arg2
        self._send(data, (self._proto, *self._local_addr, *addr))

    def _send(self, data, flowaddr):
        log_debug("socketemu send: {}->{}".format(data, str(flowaddr)))
        self._socket_queue_to_stack.put( ApplicationLayerData(timestamp=time.time(), 
            flowaddr=flowaddr, message=data) )

    def sendall(self, data, flags):
        raise NotImplementedError("sendall isn't implemented")

    def sendmsg(self, *args):
        raise NotImplementedError("*msg calls aren't implemented")

    def recvmsg(self, *args):
        raise NotImplementedError("*msg calls aren't implemented")

    def setblocking(self, flags):
        self._block = bool(flags)

    def setsockopt(self, level, option, value):
        raise NotImplementedError("set/get sockopt calls aren't implemented")

    def settimeout(self, timeout):
        self._timeout = float(timeout)

    def shutdown(self, flag):
        ApplicationLayer.unregister_socket(self)
