from abc import ABCMeta,abstractmethod
from collections import namedtuple

from .pcapffi import pcap_devices
from .lib.logging import log_debug
from .lib.exceptions import *
from .lib.address import *

ReceivedPacket = namedtuple('ReceivedPacket', 
    ['timestamp', 'input_port', 'packet'])

class LLNetBase(metaclass=ABCMeta):
    '''
    Base class for low-level networking library in Python.
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
        raise NotImplementedError("This property must be overridden by derived classes")

    @abstractmethod
    def recv_packet(self, timeout=None, timestamp=False):
        '''
        ordinarily will return the ReceivedPacket named tuple
        (timestamp, input_port, packet)
        '''
        raise NoPackets()

    @abstractmethod
    def send_packet(self, dev, packet):
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

