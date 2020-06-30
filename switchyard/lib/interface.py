from ipaddress import ip_interface, ip_address, IPv6Interface, IPv4Interface, IPv6Address, IPv4Address
from enum import Enum
from socket import if_nametoindex

from .address import EthAddr
from .logging import log_debug
from ..pcapffi import pcap_devices

class InterfaceType(Enum):
    Unknown=1
    Loopback=2
    Wired=3
    Wireless=4

class Interface(object):
    __slots__ = ['__name','__ethaddr','__ipaddrset','__ifnum','__iftype']
    __nextnum = 1

    '''
    Class that models a single logical interface on a network
    device.  An interface has a name, 48-bit Ethernet MAC address,
    and (optionally) set of IP addresses with network masks.  An interface
    also has a number associated with it and a type, which is one
    of the values of the enumerated type ``InterfaceType``.
    '''
    def __init__(self, name, ethaddr, ifnum=None, iftype=InterfaceType.Unknown):
        self.__name = name
        self.ethaddr = ethaddr
        self.__ipaddrset = set()
        self.ifnum = ifnum
        self.__iftype = iftype

    @property
    def name(self):
        '''Get the name of the interface'''
        return self.__name

    @property
    def ethaddr(self):
        '''Get the Ethernet address associated with the interface'''
        return self.__ethaddr

    @ethaddr.setter
    def ethaddr(self, value):
        if isinstance(value, EthAddr):
            self.__ethaddr = value
        elif isinstance(value, (str,bytes)):
            self.__ethaddr = EthAddr(value)
        elif value is None:
            self.__ethaddr = EthAddr('00:00:00:00:00:00')
        else:
            raise ValueError("Can't initialize ethaddr with {}".format(value))

    @property 
    def ipaddrs(self):
        '''Get the IP addresses associated with the interface, as a (frozen) set
           of ipaddress.IPv4Interface or ipaddress.IPv6Interface objects'''
        return frozenset(self.__ipaddrset)

    def assign_ipaddr(self, value):
        '''
        Assign a new IP address (v4 or v6) to this interface.
        Address can either be a IPv4Interface object, IPv6Interface object,
        or string in the form 'addr/prefix' (i.e., something that
        ipaddress.ip_interface will parse).
        '''
        if isinstance(value, (IPv4Interface, IPv6Interface)):
            self.__ipaddrset.add(value)
        elif isinstance(value, (str,IPv4Address,IPv6Address)):
            self.__ipaddrset.add(ip_interface(value))
        elif value is None:
            self.__ipaddrset.add(ip_interface('0.0.0.0'))
        else:
            raise Exception("Invalid type assignment to IP address (must be string or existing IP address) ({})".format(value))

    def remove_ipaddr(self, value):
        '''
        Remove an IP address from this interface.  Value to remove
        can be as a string or IPAddress object.
        '''
        ipa = ip_interface(value)
        for addr in self.__ipaddrset:
            if addr.ip == ipa.ip:
                self.__ipaddrset.remove(addr)
                return
        raise Exception("No such address {} exists to remove from interface".format(ipa))

    @property 
    def ifnum(self):
        '''Get the interface number (integer) associated with the interface'''
        return self.__ifnum

    @ifnum.setter
    def ifnum(self, value):
        if not isinstance(value, int):
            value = Interface.__nextnum
            Interface.__nextnum += 1
        self.__ifnum = int(value)

    @property
    def iftype(self):
        '''Get the type of the interface as a value from the InterfaceType enumeration.'''
        return self.__iftype

    def __str__(self):
        s =  "{} mac:{}".format(str(self.name), str(self.ethaddr))
        for ipa in self.ipaddrs:
            if int(ipa) != 0:
                s += " ip:{}".format(ipa)
        return s 

def make_device_list(includes=set(), excludes=set()):
    log_debug("Making device list.  Includes: {}, Excludes: {}".format(includes, excludes))
    non_interfaces = set()
    devs = set([ dev.name for dev in pcap_devices() if not dev.isloop or dev.name in includes])
    includes = set(includes) # may have been given as a list
    includes.intersection_update(devs) # only include devs that actually exist

    for d in devs:
        try:
            ifnum = if_nametoindex(d)
        except:
            non_interfaces.add(d)
    devs.difference_update(non_interfaces)
    log_debug("Devices found: {}".format(devs))

    # remove devs from excludelist
    devs.difference_update(set(excludes))

    # if includelist is non-empty, perform
    # intersection with devs found and includelist
    if includes:
        devs.intersection_update(includes)

    log_debug("Using these devices: {}".format(devs))
    return devs
