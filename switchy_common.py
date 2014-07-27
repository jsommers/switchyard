import sys
import logging

# add POX to python path in a relatively generic way;
# assumes that there is a pox subdirectory off of user's home dir
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))

from pox.lib.addresses import IPAddr,EthAddr

import curses
curses.setupterm()
setaf = curses.tigetstr('setaf')

import atexit
curses.setupterm()
def resetterm():
    print reset_term_color()
atexit.register(resetterm)

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
        if isinstance(ethaddr, EthAddr):
            self.__ethaddr = ethaddr
        else:
            self.__ethaddr = EthAddr(ethaddr)

        if isinstance(ipaddr, IPAddr):
            self.__ipaddr = ipaddr
        elif isinstance(ipaddr, str):
            self.__ipaddr = IPAddr(ipaddr)
        else:
            self.__ipaddr = ipaddr

        if isinstance(netmask, IPAddr):
            self.__netmask = netmask
        elif isinstance(netmask, str):
            self.__netmask = IPAddr(netmask)
        else:
            self.__netmask = netmask

    @property
    def name(self):
        return self.__name

    @property
    def ethaddr(self):
        return self.__ethaddr

    @property 
    def ipaddr(self):
        return self.__ipaddr

    @property 
    def netmask(self):
        return self.__netmask

    def __str__(self):
        return "{} mac:{} ip {}/{}".format(str(self.name), str(self.ethaddr), str(self.ipaddr), str(self.netmask))

def term_color(s):
    '''
    Convenience function for setting foreground color.
    '''
    colordict = {
        'green':curses.COLOR_GREEN,
        'blue':curses.COLOR_BLUE,
        'red':curses.COLOR_RED,
        'yellow':curses.COLOR_YELLOW
    }
    if s in colordict:
        return curses.tparm(setaf,colordict[s])
    else:
        return curses.tparm(curses.tigetstr('op'))

def reset_term_color():
    '''
    Convenience function for resetting terminal color.
    '''
    return curses.tparm(curses.tigetstr('op')) 

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
    logging.fatal("{}{}{}".format(term_color('red'), s, reset_term_color()))

def log_debug(s):
    '''Convenience function for debugging message.'''
    logging.debug("{}{}".format(s, reset_term_color()))

def log_warn(s):
    '''Convenience function for warning message.'''
    logging.warn("{}{}{}".format(term_color('red'), s, reset_term_color()))

def log_info(s):
    '''Convenience function for info message.'''
    logging.info("{}{}".format(s, reset_term_color()))

# decorate the "real" debugger entrypoint by
# disabling any SIGALRM invocations -- just ignore
# them if we're going into the debugger
import pdb
def setup_debugger(real_debugger):
    def inner():
        from switchy import disable_timer
        disable_timer()
        return real_debugger
    return inner()
debugger = setup_debugger(pdb.set_trace)

