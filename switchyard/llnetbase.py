from abc import ABCMeta,abstractmethod

from .pcapffi import pcap_devices
from .lib.log_support import log_debug

class LLNetBase(metaclass=ABCMeta):
    '''
    Base class for low-level networking library in Python.
    '''
    def __init__(self, name=None):
        self.devupdown_callback = None
        self.devinfo = {} # dict(str -> Interface)

    def set_devupdown_callback(self, callback):
        '''
        Set the callback function to be invoked when
        an interface goes up or down.  The arguments to the
        callback are: Interface (object representing the interface
        that has changed status), string (either 'up' or 'down').

        (function) -> None
        '''
        self.devupdown_callback = callback

    def interfaces(self):
        '''
        Return a list of interfaces incident on this node/router.
        Each item in the list is an Interface object, each of which includes
        name, ethaddr, ipaddr, and netmask attributes.
        '''
        return list(self.devinfo.values())

    def ports(self):
        '''
        Alias for interfaces() method.
        '''
        return list(self.interfaces())

    def interface_by_name(self, name):
        '''
        Given a device name, return the corresponding interface object
        '''
        if name in self.devinfo:
            return self.devinfo[name]
        raise SwitchyException("No device named {}".format(name))

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
        for devname,iface in self.devinfo.items():
            if iface.ipaddr == ipaddr:
                return iface
        raise SwitchyException("No device has IP address {}".format(ipaddr))

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
        for devname,iface in self.devinfo.items():
            if iface.ethaddr == macaddr:
                return iface
        raise SwitchyException("No device has MAC address {}".format(macaddr))

    def port_by_macaddr(self, macaddr):
        '''
        Alias for interface_by_macaddr
        '''
        return self.interface_by_macaddr(macaddr)

    @abstractmethod
    def recv_packet(self, timeout=None, timestamp=False):
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
        for devname,iface in self.devinfo.items():
            if iface.ifnum == ifnum:
                return devname
        raise SwitchyException("No device has ifnum {}".format(ifnum)) 

