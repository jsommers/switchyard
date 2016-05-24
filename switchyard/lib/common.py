import switchyard.versioncheck

import sys
import logging
from abc import ABCMeta,abstractmethod
from ipaddress import ip_interface

from switchyard.lib.address import IPAddr,EthAddr
from switchyard.lib.textcolor import *
from switchyard.lib.pcapffi import pcap_devices
from switchyard.lib.debug import debugger

class SwitchyException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.message

class ScenarioFailure(SwitchyException):
    pass

class Shutdown(Exception):
    '''Exception that is raised in user Switchyard program when the
    framework is being shut down.'''
    pass

class NoPackets(Exception):
    '''Exception that is raised in user Switchyard program when
    the recv_packet() method is called on the net object and there
    are no packets available.'''
    pass


class Interface(object):
    __slots__ = ['__name','__ethaddr','__ipaddr','__ifnum']
    __nextnum = 0

    '''
    Class that models a single logical interface on a network
    device.  An interface has a name, 48-bit Ethernet MAC address,
    and (optionally) an IP address.  The IP address is stored
    as an ipaddress.IPv4/6Interface object, which includes
    the netmask/prefixlen.
    '''
    def __init__(self, name, ethaddr, ipaddr, netmask=None, ifnum=None):
        self.__name = name
        self.ethaddr = ethaddr
        if netmask:
            ipaddr = "{}/{}".format(ipaddr,netmask)
        self.ipaddr = ipaddr
        self.ifnum = ifnum

    @property
    def name(self):
        return self.__name

    @property
    def ethaddr(self):
        return self.__ethaddr

    @ethaddr.setter
    def ethaddr(self, value):
        if isinstance(value, EthAddr):
            self.__ethaddr = value
        elif isinstance(value, str):
            self.__ethaddr = EthAddr(value)
        elif value is None:
            self.__ethaddr = EthAddr('00:00:00:00:00:00')
        else:
            self.__ethaddr = value

    @property 
    def ipaddr(self):
        return self.__ipaddr.ip

    @ipaddr.setter
    def ipaddr(self, value):
        if isinstance(value, (str,IPAddr)):
            self.__ipaddr = ip_interface(value)
        elif value is None:
            self.__ipaddr = ip_interface('0.0.0.0')
        else:
            raise Exception("Invalid type assignment to IP address (must be string or existing IP address)")

    @property 
    def netmask(self):
        return self.__ipaddr.netmask

    @netmask.setter
    def netmask(self, value):
        if isinstance(value, (IPAddr,str,int)):
            self.__ipaddr = ip_interface("{}/{}".format(self.__ipaddr.ip, str(value)))
        elif value is None:
            self.__ipaddr = ip_interface("{}/32".format(self.__ipaddr.ip))
        else:
            raise Exception("Invalid type assignment to netmask (must be IPAddr, string, or int)")

    @property 
    def ifnum(self):
        return self.__ifnum

    @ifnum.setter
    def ifnum(self, value):
        if not isinstance(value, int):
            value = Interface.__nextnum
            Interface.__nextnum += 1
        self.__ifnum = int(value)

    def __str__(self):
        s =  "{} mac:{}".format(str(self.name), str(self.ethaddr))
        if int(self.ipaddr) != 0:
            s += " ip:{}".format(self.__ipaddr)
        return s 

def setup_logging(debug):
    '''
    Setup logging format and log level.
    '''
    if debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(format="%(asctime)s %(levelname)8s %(message)s", datefmt="%H:%M:%S %Y/%m/%d", level=level)

def log_failure(s):
    '''Convenience function for failure message.'''
    with red():
        logging.fatal("{}".format(s))

def log_debug(s):
    '''Convenience function for debugging message.'''
    logging.debug("{}".format(s))

def log_warn(s):
    '''Convenience function for warning message.'''
    with magenta():
        logging.warning("{}".format(s))

def log_info(s):
    '''Convenience function for info message.'''
    logging.info("{}".format(s))


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

def make_device_list(includes, excludes):
    log_debug("Making device list.  Includes: {}, Excludes: {}".format(includes, excludes))
    # devs = set([ dev.name for dev in pcap_devices() if dev.isrunning and not dev.isloop ])
    devs = set([ dev.name for dev in pcap_devices() if not dev.isloop or dev.name in includes])
    log_debug("Devices found: {}".format(devs))

    # remove devs from excludelist
    devs.difference_update(set(excludes))

    # if includelist is non-empty, perform
    # intersection with devs found and includelist
    if includes:
        devs.intersection_update(set(includes))

    log_debug("Using these devices: {}".format(devs))
    return devs
