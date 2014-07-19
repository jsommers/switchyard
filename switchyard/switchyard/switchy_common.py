import sys
import logging
from switchyard.lib.address import IPAddr,EthAddr
from switchyard.lib.textcolor import *


class SwitchyException(Exception):
    pass

class Shutdown(Exception):
    pass

class NoPackets(Exception):
    pass

class ScenarioFailure(Exception):
    pass

class PacketFormatter(object):
    __fulldisp = False

    @staticmethod
    def full_display():
        PacketFormatter.__fulldisp = True

    @staticmethod
    def format_pkt(pkt, cls=None):
        '''
        Return a string representation of a packet.  If display_class is a known
        header type, just show the string repr of that header.  Otherwise, dump
        the whole thing.
        '''
        if PacketFormatter.__fulldisp:
            cls = None
            
        if cls:
            if not pkt.parsed:
                raw = pkt.pack()
                pkt.parse(raw)
            header = pkt.find(cls)
            if header is not None:
                return str(header)
        return str(pkt.dump())

class Interface(object):
    '''
    Class that models a single logical interface on a network
    device.  An interface has a name, 48-bit Ethernet MAC address,
    and a 32-bit IPv4 address and mask.
    '''
    def __init__(self, name, ethaddr, ipaddr, netmask):
        self.__name = name
        self.ethaddr = ethaddr
        self.ipaddr = ipaddr
        self.netmask = netmask

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
            self.__ethaddr = '00:00:00:00:00:00'
        else:
            self.__ethaddr = value

    @property 
    def ipaddr(self):
        return self.__ipaddr

    @ipaddr.setter
    def ipaddr(self, value):
        if isinstance(value, IPAddr):
            self.__ipaddr = value
        elif isinstance(value, str):
            self.__ipaddr = IPAddr(value)
        elif value is None:
            self.__ipaddr = '0.0.0.0'
        else:
            self.__ipaddr = value

    @property 
    def netmask(self):
        return self.__netmask

    @netmask.setter
    def netmask(self, value):
        if isinstance(value, IPAddr):
            self.__netmask = value
        elif isinstance(value, str):
            self.__netmask = IPAddr(value)
        elif value is None:
            self.__netmask = '255.255.255.255'
        else:
            self.__netmask = value

    def __str__(self):
        return "{} mac:{} ip:{}/{}".format(str(self.name), str(self.ethaddr), str(self.ipaddr), str(self.netmask))

def setup_logging(debug):
    '''
    Setup logging format and log level.
    '''
    if debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(format="%(asctime)s %(levelname)8s %(message)s", datefmt="%T %Y/%m/%d", level=level)

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
        logging.warn("{}".format(s))

def log_info(s):
    '''Convenience function for info message.'''
    logging.info("{}".format(s))

# decorate the "real" debugger entrypoint by
# disabling any SIGALRM invocations -- just ignore
# them if we're going into the debugger
import pdb
def setup_debugger(real_debugger):
    def inner():
        from switchyard.switchyard.switchy import disable_timer
        disable_timer()
        return real_debugger
    return inner()
debugger = setup_debugger(pdb.set_trace)

