from ipaddress import ip_interface

from .address import IPAddr,EthAddr
from ..pcapffi import pcap_devices

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

