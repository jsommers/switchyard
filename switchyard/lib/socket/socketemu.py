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
from time import time
import importlib

# carefully control what we export to user code; we provide our own
# implementation for some symbols, and others simply aren't supported
explist = copy(socket.__all__)
dontimport = ('setdefaulttimeout', 'getdefaulttimeout', 'has_ipv6', 
    'socket', 'socketpair', 'fromfd', 'dup', 'create_connection')
for name in dontimport:
    explist.remove(name)
explist.append('ApplicationLayer')
__all__ = explist

from socket import *

from ...hostfirewall import Firewall
from ...pcapffi import PcapLiveDevice
from ..exceptions import NoPackets
from ..logging import log_debug, log_info, log_warn, setup_logging, red, yellow
from ..packet import IPProtocol
from ..address import ip_address

has_ipv6 = True

def _gather_ports():
    portset = set()
    out = getoutput("netstat -an | grep ^udp")
    for x in out.split('\n'):
        fields = x.split()
        if len(fields) < 5:
            continue
        ports = fields[3].strip()
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

_default_timeout = None

def getdefaulttimeout():
    return _default_timeout

def setdefaulttimeout(tmo):
    global _default_timeout
    _default_timeout = tmo

def _normalize_addrs(addrtuple):
    return (ip_address(addrtuple[0]), int(addrtuple[1]))

def _stringify_addrs(addrtuple):
    return (str(addrtuple[0]), int(addrtuple[1]))

class ApplicationLayer(object):
    _isinit = False
    _to_app = None
    _from_app = None

    def __init__(self):
        '''
        Don't try to create an instance of this class.  Switchyard internally
        handles initialization.  Users should only ever call the
        recv_from_app() and send_to_app() static methods.
        '''
        raise RuntimeError("Ouch.  Please don't try to create an instance "
                           "of {}.  Use the static init() method "
                           "instead.".format(self.__class__.__name__))
    @staticmethod
    def _init():
        '''
        Internal switchyard static initialization method.  
        '''
        if ApplicationLayer._isinit:
            return
        ApplicationLayer._isinit = True
        ApplicationLayer._to_app = {}
        ApplicationLayer._from_app = Queue()

    @staticmethod
    def _emuports():
        s = set()
        for sockid,_ in ApplicationLayer._to_app.items():
            s.add(sockid[-1])
        return s

    @staticmethod
    def recv_from_app(timeout=_default_timeout):
        '''
        Called by a network stack implementer to receive application-layer
        data for sending on to a remote location.  

        Can optionally take a timeout value.  If no data are available,
        raises NoPackets exception.

        Returns a 2-tuple: flowaddr and data.
        The flowaddr consists of 5 items: protocol, localaddr, localport, remoteaddr,
        remoteport.
        '''
        try:
            return ApplicationLayer._from_app.get(timeout=timeout)
        except Empty:
            pass
        raise NoPackets()

    @staticmethod
    def send_to_app(proto, local_addr, remote_addr, data):
        '''
        Called by a network stack implementer to push application-layer
        data "up" from the stack.

        Arguments are protocol number, remote_addr, and local_addr.  The
        two address arguments are two-tuples with address and port (or some
        other integer end-point identifier). 

        Returns None.
        '''
        proto = IPProtocol(proto)
        local_addr = _normalize_addrs(local_addr)
        remote_addr = _normalize_addrs(remote_addr)
        xtup = (proto, local_addr[0], local_addr[1])
        sockqueue = ApplicationLayer._to_app.get(xtup, None)
        if sockqueue is not None:
            sockqueue.put((local_addr,remote_addr,data))
        else:
            log_warn("No socket queue found for local proto/address: {}".format(xtup))

    @staticmethod
    def _register_socket(s):
        '''
        Internal method used by socket emulation layer to create a new "upward"
        queue for an app-layer socket and to register the socket object.
        Returns two queues: "downward" (fromapp) and "upward" (toapp).
        '''
        queue_to_app = Queue()
        ApplicationLayer._to_app[s._sockid()] = queue_to_app
        return ApplicationLayer._from_app, queue_to_app

    @staticmethod
    def _registry_update(s, oldid):
        '''
        Internal method used to update an existing socket registry when the socket
        is re-bound to a different local port number.  Requires the socket object
        and old sockid.  Returns None.
        '''
        sock_queue = ApplicationLayer._to_app.pop(oldid)
        ApplicationLayer._to_app[s._sockid()] = sock_queue

    @staticmethod
    def _unregister_socket(s):
        '''
        Internal method used to remove the socket from AppLayer registry.
        Warns if the "upward" socket queue has any left-over data.  
        '''
        sock_queue = ApplicationLayer._to_app.pop(s._sockid())
        if not sock_queue.empty():
            log_warn("Socket being destroyed still has data enqueued for application layer.")


class socket(object):
    __slots__ =  ('_family','_socktype','_protoname','_proto',
        '_timeout','_block','_remote_addr','_local_addr',
        '_socket_queue_app_to_stack','_socket_queue_stack_to_app')

    def __init__(self, family, xtype, proto=0, fileno=0):
        family = AddressFamily(family)
        if family not in (AddressFamily.AF_INET, AddressFamily.AF_INET6):
            raise NotImplementedError(
                "socket for family {} not implemented".format(family))
        # only UDP is supported right now...
        if xtype not in (SOCK_DGRAM,):
            raise NotImplementedError(
                "socket type {} not implemented".format(xtype))
        self._family = family
        self._socktype = xtype
        self._protoname = 'udp'
        self._proto = IPProtocol.UDP
        if proto != 0:
            self._proto = proto
        self._timeout = _default_timeout
        self._block = True
        self._remote_addr = (None,None)
        self._local_addr = (ip_address('127.0.0.1'),_get_ephemeral_port())
        self.__set_fw_rules() 
        self._socket_queue_app_to_stack, self._socket_queue_stack_to_app = \
            ApplicationLayer._register_socket(self)

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
        except Exception as e:
            with yellow():
                print ("Unable to complete socket emulation setup (failed on "
                       "firewall/bpf filter installation).  Did you start the "
                       " program via switchyard?")
                import traceback
            print ("Here is the raw exception information:")
            with red():
                print(indent(traceback.format_exc(), '    '))
            raise e

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
        return (IPProtocol(self._proto), self._local_addr[0], self._local_addr[1])

    def _flowaddr(self):
        return (self._proto, self._local_addr[0], self._local_addr[1], 
            self._remote_addr[0], self._remote_addr[1]) 

    def accept(self):
        raise NotImplementedError()

    def close(self):
        try:
            ApplicationLayer._unregister_socket(self)
        except:
            # ignore any errors (e.g., double-close)
            pass
        return 0

    def bind(self, address):
        portset = _gather_ports().union(ApplicationLayer._emuports())
        if address[1] in portset:
            log_warn("Port is already in use.")
            return -1

        oldid = self._sockid()
        # block firewall port
        # set stack to only allow packets through for addr/port
        self._local_addr = _normalize_addrs(address)
        # update firewall and pcap filters
        self.__set_fw_rules()
        ApplicationLayer._registry_update(self, oldid)
        return 0

    def connect(self, address):
        self._remote_addr = _normalize_addrs(address)
        return 0

    def connect_ex(self, address):
        self._remote_addr = _normalize_addrs(address)
        return 0

    def getpeername(self):
        return _stringify_addrs(self._remote_addr)

    def getsockname(self):
        return _stringify_addrs(self._local_addr)

    def getsockopt(self, level, option, buffersize=0):
        raise NotImplementedError()

    def gettimeout(self):
        return self._timeout

    @property 
    def timeout(self):
        return self._timeout

    def listen(self, backlog):
        raise NotImplementedError()

    def recv(self, buffersize, flags=0):
        _,_,data = self._recv(buffersize)
        return data

    def recv_into(self, *args):
        raise NotImplementedError("*_into calls aren't implemented")

    def recvfrom(self, buffersize, flags=0):
        _,remoteaddr,data = self._recv(buffersize)
        return data,remoteaddr

    def recvfrom_into(self, *args):
        raise NotImplementedError("*_into calls aren't implemented")

    def _recv(self, nbytes):
        try:
            localaddr,remoteaddr,data = self._socket_queue_stack_to_app.get(
                block=self._block, timeout=self._timeout)
            return _stringify_addrs(localaddr),_stringify_addrs(remoteaddr),data
        except Empty as e:
            pass
        raise timeout("timed out")

    def send(self, data, flags=0):
        if self._remote_addr == (None,None):
            raise sockerr("ENOTCONN: socket not connected")
        return self._send(data, self._flowaddr())

    def sendto(self, data, *args):
        remoteaddr = args[-1]
        remoteaddr = _normalize_addrs(remoteaddr)
        return self._send(data, (self._proto, self._local_addr[0], 
            self._local_addr[1], remoteaddr[0], remoteaddr[1]))

    def _send(self, data, flowaddr):
        self._socket_queue_app_to_stack.put( (flowaddr, data) )
        return len(data)

    def sendall(self, *args):
        raise NotImplementedError("sendall isn't implemented")

    def sendmsg(self, *args):
        raise NotImplementedError("*msg calls aren't implemented")

    def recvmsg(self, *args):
        raise NotImplementedError("*msg calls aren't implemented")

    def setblocking(self, flags):
        self._block = bool(flags)
        if self._block:
            self._timeout = None
        else:
            self._timeout = 0.0

    def setsockopt(self, *args):
        raise NotImplementedError("set/get sockopt calls aren't implemented")

    def settimeout(self, timeout):
        if timeout is None:
            self._timeout = None
            self._block = True
        else:
            self._timeout = float(timeout)
            self._block = self._timeout == 0

    def shutdown(self, flag):
        try:
            ApplicationLayer._unregister_socket(self)
        except:
            pass
        return 0
