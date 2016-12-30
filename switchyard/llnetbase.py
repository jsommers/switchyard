from abc import ABCMeta,abstractmethod
from collections import namedtuple

from .pcapffi import pcap_devices
from .lib.logging import log_debug, log_warn
from .lib.exceptions import *
from .lib.address import *

ReceivedPacket = namedtuple('ReceivedPacket', 
    ['timestamp', 'input_port', 'packet'])

def _start_usercode(entryfunction, netobj, codeargdict):
    '''
    figure out how to correctly start the user code.  warn if
    args are passed on the command line, but the code doesn't 
    accept them.
    '''
    # p22, python3 lang ref
    takenet = entryfunction.__code__.co_argcount >= 1
    takeargs = entryfunction.__code__.co_flags & 0x04 == 0x04
    takekw = entryfunction.__code__.co_flags & 0x08 == 0x08

    args = codeargdict['args']
    kwargs = codeargdict['kwargs']

    if args and not takeargs:
        log_warn("User code arguments passed on command line, "
            "but the user code doesn't take arguments")
    if kwargs and not takekw:
        log_warn("User code keyword args passed on command line, "
            "but the user code doesn't take kwargs")

    if not takenet:
        raise RuntimeError("Your code does not appear to accept at "
            "least one parameter for the net object")
    if takeargs:
        if takekw:
            entryfunction(netobj, *args, **kwargs)
        else:
            entryfunction(netobj, *args)
    else:
        entryfunction(netobj)

class LLNetBase(metaclass=ABCMeta):
    '''
    Base class for the low-level networking library in Python.
    "net" objects are constructed from classes derived from this
    class.
    '''
    def __init__(self, name=None):
        self._devupdown_callback = None
        self._devinfo = {} # dict(str -> Interface)

    def set_devupdown_callback(self, callback):
        '''
        Set the callback function to be invoked when
        an interface goes up or down.  The arguments to the
        callback are: Interface (object representing the interface
        that has changed status), string (either 'up' or 'down').

        (function) -> None
        '''
        self._devupdown_callback = callback

    def intf_down(self, interface):
        '''
        Can be called when an interface goes down.
        FIXME: doesn't really do anything at this point.
        '''
        intf = self._devinfo.get(interface, None)
        if intf and self._devupdown_callback:
            self._devupdown_callback(intf, 'down')

    def intf_up(self, interface):
        '''
        Can be called when an interface is put in service.
        FIXME: not currently used; more needs to be done to
        correctly put a new intf into service.
        '''
        if interface.name not in self._devinfo:
            self._devinfo[interface.name] = interface
            if self._devupdown_callback:
                self._devupdown_callback(interface, 'up')
        else:
            raise ValueError("Interface already registered")

    def interfaces(self):
        '''
        Return a list of interfaces incident on this node/router.
        Each item in the list is an Interface object, each of which includes
        name, ethaddr, ipaddr, and netmask attributes.
        '''
        return list(self._devinfo.values())

    def ports(self):
        '''
        Alias for interfaces() method.
        '''
        return self.interfaces()

    def interface_by_name(self, name):
        '''
        Given a device name, return the corresponding interface object
        '''
        if name in self._devinfo:
            return self._devinfo[name]
        raise KeyError("No device named {}".format(name))

    def port_by_name(self, name):
        '''
        Alias for interface_by_name
        '''
        return self.interface_by_name(name)

    def interface_by_ipaddr(self, ipaddr):
        '''
        Given an IP address, return the interface that 'owns' this address
        '''
        ipaddr = IPAddr(ipaddr)
        for devname,iface in self._devinfo.items():
            if iface.ipaddr == ipaddr:
                return iface
        raise KeyError("No device has IP address {}".format(ipaddr))

    def port_by_ipaddr(self, ipaddr):
        '''
        Alias for interface_by_ipaddr
        '''
        return self.interface_by_ipaddr(ipaddr)

    def interface_by_macaddr(self, macaddr):
        '''
        Given a MAC address, return the interface that 'owns' this address
        '''
        macaddr = EthAddr(macaddr)
        for devname,iface in self._devinfo.items():
            if iface.ethaddr == macaddr:
                return iface
        raise KeyError("No device has MAC address {}".format(macaddr))

    def port_by_macaddr(self, macaddr):
        '''
        Alias for interface_by_macaddr
        '''
        return self.interface_by_macaddr(macaddr)

    @property
    def testmode(self):
        '''
        Returns True if running in test mode and False if running in
        live/real mode.
        '''
        raise NotImplementedError("This property must be overridden by derived classes")

    @abstractmethod
    def recv_packet(self, timeout=None):
        '''
        Receive a packet on any port/interface.
        If a non-None timeout is given, the method will block for up
        to timeout seconds.  If no packet is available, the exception
        NoPackets will be raised.  If the Switchyard framework is being
        shut down, the Shutdown exception will be raised.
        If a packet is available, the ReceivedPacket named tuple 
        (timestamp, input_port, packet) will be returned.
        '''
        raise NoPackets()

    @abstractmethod
    def send_packet(self, output_port, packet):
        '''
        Send a packet out the given output port/interface.  
        Returns None.
        '''
        pass

    @abstractmethod
    def shutdown(self):
        pass

    @property
    def name(self):
        pass

    def _lookup_devname(self, ifnum):
        for devname,iface in self._devinfo.items():
            if iface.ifnum == ifnum:
                return devname
        raise KeyError("No device has ifnum {}".format(ifnum)) 

