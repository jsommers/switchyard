import sys
import argparse
import os
import signal
import re
import subprocess
import time
import threading
from Queue import Queue,Empty
import importlib
import bz2 
import hashlib
import cPickle as pickle 
import base64 
import fnmatch 
import copy
from collections import namedtuple
from abc import ABCMeta,abstractmethod
import textwrap
import pdb

# global: use in any timer callbacks
# to decide whether to handle the timer or not.
# if we're in the debugger, just drop it.
in_debugger = False
def disable_timer():
    global in_debugger
    in_debugger = True

# add POX to python path in a relatively generic way;
# assumes that there is a pox subdirectory off of user's home dir
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
sys.path.append(os.getcwd())

from pox.lib.packet import ethernet,ipv4,packet_base
from pox.lib.addresses import IPAddr,EthAddr
from pox.openflow.libopenflow_01 import ofp_match
from pox.lib.packet.packet_utils import ethtype_to_str, ipproto_to_str

'''
Low-level-ish packet library for PyRouter project.  Uses libpcap
for receiving and sending packets, and the POX controller utility
libraries for packet parsing.  It is Ethernet and IPv4-centric.

jsommers@colgate.edu
'''

USERMAIN = 'switchy_main'

from switchy_common import Interface, SwitchyException, Shutdown, NoPackets, ScenarioFailure, PacketFormatter
from switchy_common import setup_logging, log_info, log_debug, log_warn, log_failure, term_color, reset_term_color


class LLNetBase(object):
    '''
    Base class for low-level networking library in Python.  
    '''
    __metaclass__ = ABCMeta

    def __init__(self):
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
        Each item in the list is an Interface (devname,macaddr,ipaddr,netmask) object.
        '''
        return self.devinfo.values()

    def ports(self):
        '''
        Alias for interfaces() method.
        '''
        return self.interfaces()

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
        for devname,iface in self.devinfo.iteritems():
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
        for devname,iface in self.devinfo.iteritems():
            if iface.ethaddr == macaddr:
                return iface
        raise SwitchyException("No device has MAC address {}".format(macaddr))

    def port_by_macaddr(self, macaddr):
        '''
        Alias for interface_by_macaddr
        '''
        return self.interface_by_macaddr(macaddr)

    @abstractmethod
    def recv_packet(self, timeout=0.0, timestamp=False):
        raise NoPackets()

    @abstractmethod
    def send_packet(self, dev, packet):
        pass

    @abstractmethod
    def shutdown(self):
        pass


class PyLLNet(LLNetBase):
    '''
    A class that represents a collection of network devices
    on which packets can be received and sent.
    '''

    def __init__(self, environment, includelist, excludelist):
        LLNetBase.__init__(self)
        signal.signal(signal.SIGINT, PyLLNet.__sig_handler)
        signal.signal(signal.SIGTERM, PyLLNet.__sig_handler)
        signal.signal(signal.SIGHUP, PyLLNet.__sig_handler)
        signal.signal(signal.SIGUSR1, PyLLNet.__sig_handler)
        signal.signal(signal.SIGUSR2, PyLLNet.__sig_handler)

        self.devs = self.__initialize_devices(environment, includelist, excludelist)
        self.devinfo = self.__assemble_devinfo()
        self.pcaps = {}
        self.__make_pcaps()
        log_info("Found network devices: {}".format(' '.join(self.devs)))
        for devname, intf in self.devinfo.iteritems():
            log_debug("{}: {}".format(devname, str(intf)))
            
        PyLLNet.running = True
        self.__spawn_threads()

    def __initialize_devices(self, env, includes, excludes):
        devs = self.__get_net_devs(env)
        print "Devs",devs
        if not devs:
            raise SwitchyException("No suitable interfaces found.")
        
        # remove devs from excludelist
        devs.difference_update(set(excludes))

        # if includelist is non-empty, perform
        # intersection with devs found and includelist
        if includes:
            devs.intersection_update(set(includes))

        if not devs:
            raise SwitchyException("No interfaces enabled after handling include/exclude lists")
        
        return devs

    def shutdown(self):
        '''
        Should be called by pynet user when a PyLLNet object is
        being shut down.  Cleans up internal threads and network
        interaction objects.
        '''
        PyLLNet.running = False
        log_debug("Joining threads for shutdown")
        for t in self.threads:
            t.join()
        log_debug("Closing pcap devices")
        for devname,pdev in self.pcaps.iteritems():
            pdev.close()
        log_debug("Done cleaning up")

    def __spawn_threads(self):
        '''
        Internal method.  Creates threads to handle low-level
        network receive.
        '''
        self.threads = []
        self.pktqueue = Queue()
        for devname,pdev in self.pcaps.iteritems():
            t = threading.Thread(target=PyLLNet.__low_level_dispatch, args=(pdev, devname, self.pktqueue))
            t.start()
            self.threads.append(t)

    def __get_net_devs(self, environment):
        '''
        Internal method.  Find all "valid" network devices
        on the host.  Assumes naming convention in 
        project mininet code.
        '''
        devs = set()
        xlist = open('/proc/net/dev').readlines()
        xlist.pop(0) # ignore header line
        # match standard mininet node naming conventions, e.g.,
        # router0-eth0, s0-eth0, switch-eth0
        if environment == 'mininet':
            pattern = re.compile('^[A-Za-z]+\d*-eth\d+') 
        else:
            pattern = re.compile('^eth\d+')

        for line in xlist:
            fields = line.split()
            if pattern.match(fields[0]):
                devs.add(fields[0].strip(':'))
        return devs

    def __assemble_devinfo(self):
        '''
        Internal method.  Assemble information on each interface/
        device that we know about, i.e., its MAC address and configured
        IP address and prefix.
        '''
        devinfo = {}

        # beautiful/ugly regular expressions
        hwaddr = re.compile("HWaddr ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})")
        ipmask = re.compile("inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+Bcast:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+Mask:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        for devname in self.devs:
            macaddr = None
            ipaddr = None
            mask = None
            output = subprocess.check_output(["ifconfig", devname])
            for line in output.split('\n'):
                mobj = hwaddr.search(line)
                if mobj:
                    macaddr = EthAddr(mobj.groups()[0])
                mobj = ipmask.search(line)
                if mobj:
                    ipaddr = IPAddr(mobj.groups()[0])
                    mask = IPAddr(mobj.groups()[2])
            devinfo[devname] = Interface(devname, macaddr, ipaddr, mask) 
        return devinfo

    def __make_pcaps(self):
        '''
        Internal method.  Create libpcap devices
        for every network interface we care about and
        set them in non-blocking mode.
        '''
        self.pcaps = {}
        for dev in self.devs:
            thismac = self.devinfo[dev].ethaddr
            pdev = pcap.pcap(name=dev) # default snaplen is 64k
            pdev.setnonblock(1)
            pdev.setfilter("not ether src {}".format(thismac))
            log_debug("Result of setting device {} in non-blocking mode: {}".format(dev, pdev.getnonblock()))
            self.pcaps[dev] = pdev

    @staticmethod
    def __sig_handler(signum, stack):
        '''
        Handle process INT signal.
        '''
        log_debug("Got SIGINT.")
        if signum == signal.SIGINT:
            PyLLNet.running = False

    @staticmethod
    def __low_level_dispatch(pcapdev, devname, pktqueue):
        '''
        Thread entrypoint for doing low-level receive and dispatch
        for a single pcap device.
        '''
        while PyLLNet.running:
            pkts_processed = pcapdev.dispatch(-1, PyLLNet.__low_level_recv, devname, pktqueue)
            if pkts_processed > 0:
                log_debug("Receiver thread {} got {} pkts".format(devname, pkts_processed))
            time.sleep(0.1)

        log_debug("Receiver thread for {} exiting".format(devname))
        nreceived, ndropped, ndroppedif = pcapdev.stats()
        log_debug("Device statistics {}: {} received, {} dropped, {} dropped/if".format(devname, nreceived, ndropped, ndroppedif))

    @staticmethod
    def __low_level_recv(ts, rawpkt, *args):
        '''
        Callback function for pcap dispatch.  Receive packet and
        enqueue it for the main thread to deliver back to user code.
        '''
        devname, pktqueue = args[0],args[1]
        ethpkt = ethernet(raw=bytes(rawpkt))
        log_debug("Got packet on device {}".format(devname))
        pktqueue.put( (devname,ts,ethpkt) )

    def recv_packet(self, timeout=0.0, timestamp=False):
        '''
        Receive packets from any device on which one is available.
        Blocks until it receives a packet.  Returns None,None,None
        when device(s) are shut down (i.e., on a SIGINT to the process).

        Returns a tuple of device,timestamp,packet, where
            device: network device name on which packet was received
                    as a string
            timestamp: floating point value of time at which packet
                    was received
            packet: POX ethernet packet object
        '''
        while PyLLNet.running:
            try:
                rv = self.pktqueue.get(timeout=timeout)
                if timestamp:
                    return rv
                else:
                    return rv[0],rv[2]
            except Empty:
                raise NoPackets()
        raise Shutdown()

    def send_packet(self, dev, packet):
        '''
        Send a POX packet (must be an ethernet packet object) on the
        given device (string name of device).

        Raises an exception if packet object isn't valid, or device
        name isn't recognized.
        '''
        pdev = self.pcaps.get(dev, None)
        if not pdev:
            raise SwitchyException("Unrecognized device name for packet send: {}".format(dev))
        else:
            if packet is None:
                raise SwitchyException("No packet object given to send_packet")
            if not isinstance(packet, ethernet):
                raise SwitchyException("Packet object given to send_packet is not a POX ethernet packet object")
            # convert packet to bytes and send it
            rawpkt = packet.pack()
            log_debug("Sending packet on device {}: {}".format(dev, str(packet)))
            pdev.inject(rawpkt, len(rawpkt))


class SwitchyTestEvent(object):
    MATCH_FAIL = 0x00
    MATCH_SUCCESS = 0x01
    MATCH_PARTIAL = 0x02

    EVENT_INPUT = 0x10
    EVENT_OUTPUT = 0x20

    __metaclass__ = ABCMeta
    def __init__(self):
        self.display = None

    @abstractmethod
    def match(self, evtype, **kwargs):
        '''
        Abstract method that must be overridden in input/output
        events.  Default for base class is to return failed match.
        '''
        return SwitchyTestEvent.MATCH_FAIL

    def format_pkt(self, pkt):
        '''
        Return a string representation of a packet.  If display_class is a known
        header type, just show the string repr of that header.  Otherwise, dump
        the whole thing.
        '''
        return PacketFormatter.format_pkt(pkt, self.display)

class PacketMatcher(object):
    '''
    Class whose job it is to define a packet template against which
    some other packet is matched, particularly for PacketOutputEvents,
    where we want to verify that a packet emitted by Switchyard app code 
    conforms to some expectation.  This class delegates some of the
    matching work to POX's openflow matcher (ofp_match).
    '''
    def __init__(self, template, *predicates, **kwargs):
        '''
        Instantiate the matcher delegate.  template is expected
        to be a POX packet object.  

        An arbitrary number of predicate functions can also be
        passed.  Each predicate function must be defined as a
        string with a single lambda.  Each lambda must take
        a single arg (a POX packet object) and return bool.

        Recognized kwargs: exact and wildcard

        exact determines whether a byte-by-byte comparison is done
        against a reference packet, or a more flexible match is done
        based on the fields available in an openflow flow table entry.

        wildcard is a list of strings that must match fields in an
        ofp_match structure.  this is only used if exact=False, and
        the effect is to wildcard those fields in the ofp_match.
        Fields: dl_src, dl_dst, dl_type, dl_vlan, dl_vlan_pcp,
        nw_src, nw_dst, nw_proto, nw_tos, tp_src, tp_dst
        '''
        self.exact = kwargs.get('exact', True)
        wildcard = kwargs.get('wildcard', None)

        if self.exact:
            self.__matchobj = copy.deepcopy(template)
        else:
            self.__matchobj = ofp_match.from_packet(template)
        self.predicates = predicates
        if self.predicates:
            for predstr in self.predicates:
                if not isinstance(predstr, basestring):
                    log_failure("Predicates passed to PacketMatcher must be strings (this is not: {})".format(predstr))
                    assert(isinstance(predstr, basestring))
        if wildcard is not None and not self.exact:
            for wfield in wildcard:
                setattr(self.__matchobj, wfield, None)

    @property
    def ofpmatch(self):
        return self.__matchobj

    def __diagnose(self, packet, results):
        '''
        Construct/return a string that describes why a packet doesn't
        match this matcher.
        '''
        firstmatch = results.pop(0)
        xtype = "exact" if self.exact else "wildcard"
        aan = 'an' if xtype == 'exact' else 'a'
        xresults = "passed" if firstmatch else "failed"
        conjunction = ', but' if firstmatch else '. '
        diagnosis = ["{} {} match {}{}".format(aan.capitalize(), xtype, xresults, conjunction)]

        for pidx,preresult in enumerate(results):
            xresults = "passed" if preresult else "failed"
            xname = self.predicates[pidx]
            diagnosis += ["when comparing the packet you sent versus what I expected, the predicate ({}) {}.".format(xname, xresults)]

        if firstmatch:
            diagnosis += ["\nThese fields matched: {}.".format(self.show(None))]
        else:
            diagnosis += ["\nHere is the packet that failed the check: {}.".format(packet.dump())]
            if self.exact:
                diagnosis += ["\nHere is exactly what I expected: {}.".format(self.__matchobj.dump())]
            else:
                diagnosis += ["\nHere is what I expected to match: {}.".format(self.show(None))]
        return ' '.join(diagnosis)

    def match(self, packet):
        '''
        Determine whether packet matches our expectation.
        The packet is only a match if it meets ofp_match
        criteria, and all predicates return True.
        If no match, then construct a "nice" description
            of what doesn't match, and throw an exception.
        '''
        if self.exact:
            # compare packed packet contents for exact match
            results = [ copy.deepcopy(packet).pack() == self.__matchobj.pack() ]
        else:
            # compare with OFP match + wildcards
            results = [ self.__matchobj.matches_with_wildcards(ofp_match.from_packet(packet)) ]
        results += [ eval(fn)(packet) for fn in self.predicates ]
        if all(results):
            return True
        else:
            raise ScenarioFailure(self.__diagnose(packet, results))

    def show(self, cls):
        if self.exact:
            return PacketFormatter.format_pkt(self.__matchobj, cls)
        else:
            # show the ofp_match details.
            # return self.__matchobj.show() is too detailed
            def fmtfield(f, wildcardview='*', convert=None):
                v = self.__matchobj.__getattr__(f)
                if v is None or f.startswith('tp') and v == 0:
                    return wildcardview
                else:
                    if convert:
                        return convert(v)
                    return v
            dl = nw = tp = ''
            if cls is None or cls.__name__ == 'ethernet':
                dl = "[{}->{} {}]".format(fmtfield('dl_src', '**:**:**:**:**:**'), 
                                          fmtfield('dl_dst', '**:**:**:**:**:**'), 
                                          fmtfield('dl_type', convert=ethtype_to_str))
            if cls is None or cls.__name__ == 'ipv4':
                nw = " IP {}->{} ".format(fmtfield('nw_src', '*.*.*.*'),
                                          fmtfield('nw_dst', '*.*.*.*'))
            if cls is None or cls.__name__ in ['tcp','udp','icmp']:
                arrow = ':' if cls is None or cls.__name__ == 'icmp' else '->'
                tp = " {} {}{}{}".format(fmtfield('nw_proto', convert=ipproto_to_str),fmtfield('tp_src'), arrow, fmtfield('tp_dst'))
            return dl + nw + tp
            # not including dl_vlan, dl_vlan_pcp

class PacketInputTimeoutEvent(SwitchyTestEvent):
    '''
    Test event that models a timeout when trying to receive
    a packet.  No packet arrives, so the switchy app should
    handle a NoPackets exception and continue
    '''
    def __init__(self, timeout):
        self.timeout = timeout

    def __getstate__(self):
        return self.__dict__.copy()

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)

    def __eq__(self, other):
        return self.device == other.device and str(self.packet) == str(other.packet)

    def __str__(self):
        return "timeout on recv_packet"

    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketInputEvent currently ignores
        any additional arguments.
        '''
        if evtype == SwitchyTestEvent.EVENT_INPUT:
            return SwitchyTestEvent.MATCH_SUCCESS
        else:
            return SwitchyTestEvent.MATCH_FAIL

    def generate_packet(self, use_timestamp, timestamp):
        time.sleep(self.timeout)
        raise NoPackets()
 

class PacketInputEvent(SwitchyTestEvent):
    '''
    Test event that models a packet arriving at a router/switch
    (e.g., a packet that we generate).
    '''
    def __init__(self, device, packet, display=None):
        self.device = device
        self.packet = packet
        self.display = display

    def __getstate__(self):
        return self.__dict__.copy()

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)

    def __eq__(self, other):
        return self.device == other.device and str(self.packet) == str(other.packet)

    def __str__(self):
        return "recv_packet {} on {}".format(self.format_pkt(self.packet), self.device)

    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketInputEvent currently ignores
        any additional arguments.
        '''
        if evtype == SwitchyTestEvent.EVENT_INPUT:
            return SwitchyTestEvent.MATCH_SUCCESS
        else:
            return SwitchyTestEvent.MATCH_FAIL

    def generate_packet(self, use_timestamp, timestamp):
        # ensure that the packet is fully parsed before
        # delivering it.  cost is immaterial since this
        # is just testing code!
        self.packet = ethernet(raw=self.packet.pack())
        if use_timestamp:
            return self.device, timestamp, self.packet
        else:
            return self.device, self.packet

class PacketOutputEvent(SwitchyTestEvent):
    '''
    Test event that models a packet that should be emitted by
    a router/switch.
    '''
    def __init__(self, *args, **kwargs):
        self.matches = {}
        self.device_packet_map = {}
        self.display = None
        if 'display' in kwargs:
            self.display = kwargs['display']
        exact = kwargs.get('exact', True)
        wildcard = kwargs.get('wildcard', [])
        predicates = kwargs.get('predicates', [])

        if len(args) % 2 != 0:
            raise Exception("Arg list length to PacketOutputEvent must be even (device1, pkt1, device2, pkt2, etc.)")
        for i in range(0, len(args), 2):
            matcher = PacketMatcher(args[i+1], *predicates, exact=exact, wildcard=wildcard)
            self.device_packet_map[args[i]] = matcher
  
    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketOutputEvent requires
        two additional keyword args: device (str) nd packet (POX packet object).
        '''
        if evtype != SwitchyTestEvent.EVENT_OUTPUT:
            return SwitchyTestEvent.MATCH_FAIL
        if 'device' not in kwargs or 'packet' not in kwargs:
            return SwitchyTestEvent.MATCH_FAIL
        device = kwargs['device']
        pkt = kwargs['packet']

        if device in self.device_packet_map:
            matcher = self.device_packet_map[device]
            if matcher.match(pkt):
            # if self.packets_match(pkt, self.device_packet_map[device]):
                self.matches[device] = pkt
                del self.device_packet_map[device]
                if len(self.device_packet_map) == 0:
                    return SwitchyTestEvent.MATCH_SUCCESS
                else:
                    return SwitchyTestEvent.MATCH_PARTIAL
            else:
                raise ScenarioFailure("test failed when you called send_packet: output device {} is ok, but\n\t{}\n\tdoesn't match what I expected\n\t{}".format(device, self.format_pkt(pkt, self.display), matcher.show(self.display)))
        else:
            raise ScenarioFailure("test failed when you called send_packet: output on device {} unexpected (I expected this: {})".format(device, str(self)))

    def __str__(self):
        s = "send_packet(s) "
        devlist = ["{} out {}".format(v.show(self.display),k) for k,v in self.device_packet_map.iteritems() ]
        devlist += ["{} out {}".format(self.format_pkt(v),k) for k,v in self.matches.iteritems() ]
        s += ' and '.join(devlist) 
        return s

    def __getstate__(self):
        return self.__dict__.copy()

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)

    def __eq__(self, other):
        return str(self) == str(other) 


TestScenarioEvent = namedtuple('TestScenarioEvent', ['event','description','timestamp'])

class Scenario(object):
    '''
    Test scenario definition.  Given a list of packetio event objects,
    generates input events and tests/verifies output events.
    '''
    def __init__(self, name):
        self.interface_map = {}
        self.name = name
        self.pending_events = []
        self.completed_events = []
        self.timer = False
        self.next_timestamp = 0.0
        self.timeoutval = 10

    def reset(self):
        '''
        Clear out completed events; put all events into pending.
        Reset timer and timestamp.
        '''
        self.pending_events += self.completed_events
        self.completed_events = []
        self.next_timestamp = 0.0
        self.timer = False

    def add_interface(self, interface_name, macaddr, ipaddr=None, netmask=None):
        '''
        Add an interface to the test scenario.

        (str, str/EthAddr, str/IPAddr, str/IPAddr) -> None
        '''
        intf = Interface(interface_name, macaddr, ipaddr, netmask)
        self.interface_map[interface_name] = intf

    def interfaces(self):
        return self.interface_map

    def ports(self):
        ''' 
        Alias for interfaces() method.
        '''
        return self.interfaces()
        
    def expect(self, event, description):
        '''
        Add a new event and description to the expected set of events 
        to occur for this test scenario.

        (Event object, str) -> None
        '''
        self.pending_events.append( TestScenarioEvent(event, description, self.next_timestamp) )
        self.next_timestamp += 1.0

    def get_failed_test(self):
        '''
        Return the head of the pending_events queue.  In the case of failure,
        this is the expectation that wasn't met.
        '''
        if self.pending_events:
            return self.pending_events[0]
        return None
        
    def next(self):
        '''
        Return the next expected event to happen.
        '''
        if not self.pending_events:
            raise ScenarioFailure("next() called on scenario{}, but not expecting anything else for this scenario".format(self.name))
        else:
            return self.pending_events[0].event
            
    def testfail(self, message):
        '''
        Method to call if the current expected event does not
        occur, i.e., the test expectation wasn't met.
        '''
        raise ScenarioFailure("{}".format(message))
        
    def timer_expiry(self, signum, stackframe):
        '''
        Callback method for ensuring that send_packet gets called appropriately
        from user code (i.e., code getting tested).
        '''
        if in_debugger:
            self.timer = False
            return

        if self.timer:
            log_debug("Timer expiration while expecting PacketOutputEvent")
            raise ScenarioFailure("Expected send_packet to be called to match {} in scenario {}, but it wasn't called, and after {} seconds I gave up.".format(str(self.pending_events[0]), self.name, self.timeoutval))
        else:
            log_debug("Ignoring timer expiry with timer=False")

    def cancel_timer(self):
        '''
        Don't let any pending SIGALRM interrupt things.
        '''
        self.timer=False

    def testpass(self):
        '''
        Method to call if the current expected event occurs, i.e., an event
        expectation has been met.

        Move current event (head of pending list) to completed list and disable
        any timers that may have been started.
        '''
        self.timer = False
        ev = self.pending_events.pop(0)
        log_debug("Test pass: {} - {}".format(ev.description, str(ev.event)))
        self.completed_events.append(ev)

        if not len(self.pending_events):
            return

        # if head of expected is pktout, set alarm for 1 sec
        # or so to check that we actually receive a packet.
        if isinstance(self.pending_events[0].event, PacketOutputEvent):
            log_debug("Setting timer for next PacketOutputEvent")
            signal.alarm(self.timeoutval)
            signal.signal(signal.SIGALRM, self.timer_expiry)
            self.timer = True

        log_debug("Next event expected: "+str(self.pending_events[0].event))

    @staticmethod
    def wrapevent(description, expected_event):
        '''
        Create a "pretty" version of an event description and expectation for output.
        '''
        baseindent = 4
        wraplen = 60
        expected_event = "Expected event: {}".format(expected_event)

        outstr = '\n'.join([' ' * baseindent + s for s in textwrap.wrap(description, wraplen)]) + '\n'
        outstr += '\n'.join([' ' * (baseindent*2) + s for s in textwrap.wrap(expected_event, wraplen)])
        return outstr

    def print_summary(self):
        '''
        Print a semi-nice summary of the test scenario: what passed, what
        failed, and test components that haven't been checked yet due to
        a prior failure.
        '''
        print "\n{}Results for test scenario {}:".format(term_color('blue'), self.name),
        print "{} passed, {} failed, {} pending".format(len(self.completed_events), min(1,len(self.pending_events)), max(0,len(self.pending_events)-1))

        if len(self.completed_events):
            print "\n{}Passed:".format(term_color('green'))
            for idx,ev in enumerate(self.completed_events):
                idxstr = str(idx+1)
                print "{}{}{}".format(idxstr, term_color('green'), self.wrapevent(ev.description, str(ev.event))[len(idxstr):])

        if len(self.pending_events):
            print "\n{}Failed:".format(term_color('red'))
            failed_event = self.pending_events[0]
            print "{}{}".format(term_color('red'), self.wrapevent(failed_event.description, str(failed_event.event)))
            if len(self.pending_events) > 1:
                print "\n{}Pending (couldn't test because of prior failure):".format(term_color('yellow'))
                for idx,ev in enumerate(self.pending_events[1:]):
                    idxstr = str(idx+1)
                    print "{}{}{}".format(idxstr, term_color('yellow'), self.wrapevent(ev.description, str(ev.event))[len(idxstr):])
        print

    def done(self):
        '''
        Boolean method that tests whether the test scenario
        is done or not.
        '''
        return len(self.pending_events) == 0
 
    def __str__(self):
        return "scenario {}".format(self.name)

    def __getstate__(self):
        odict = self.__dict__.copy()
        del odict['timer']
        odict['events'] = odict['pending_events'] + odict['completed_events']
        del odict['pending_events']
        del odict['completed_events']
        del odict['next_timestamp']
        return odict

    def __setstate__(self, xdict):
        xdict['pending_events'] = xdict['events']
        del xdict['events']
        xdict['next_timestamp'] = 0.0
        xdict['timer'] = None
        xdict['completed_events'] = []
        self.__dict__.update(xdict)

    def __eq__(self, other):
        if self.next_timestamp != other.next_timestamp:
            return False
        if len(self.pending_events) != len(other.pending_events):
            return False
        if len(self.completed_events) != len(other.completed_events):
            return False
        for i in range(len(self.pending_events)):
            if self.pending_events[i] != other.pending_events[i]:
                return False
        for i in range(len(self.completed_events)):
            if self.completed_events[i] != other.completed_events[i]:
                return False
        return True

    def scenario_sanity_check(self):
        '''
        Perform some basic sanity checks on a test scenario object:
        - make sure that events refer to devices that are registered
        - check that there are both input/output events
        
        Just carp warnings if anything looks incorrect, but don't
        fail: punt the problem to the user.

        Returns nothing.
        '''
        log_debug("Doing sanity check on test scenario {}".format(self.name))
        for ev in self.pending_events:
            if isinstance(ev.event, PacketInputEvent):
                if ev.event.device not in self.interface_map:
                    log_warn("PacketInputEvent ({}) refers to a device not part of scenario interface map".format(str(ev.event)))
                if not isinstance(ev.event.packet, ethernet):
                    log_warn("PacketInputEvent ({}) refers to a non-packet object ({})".format(str(ev.event), type(ev.event.packet)))
            elif isinstance(ev.event, PacketOutputEvent):
                if not len(ev.event.device_packet_map):
                    log_warn("PacketOutputEvent ({}) doesn't have any output devices included".format(ev.event))
                for dev,pkt in ev.event.device_packet_map.iteritems():
                    if dev not in self.interface_map:
                        log_warn("PacketOutputEvent () refers to a device not part of scenario interface map".format(str(ev.event)))
                    if not isinstance(pkt, PacketMatcher):
                        log_warn("PacketOutputEvent ({}) refers to a non-PacketMatcher object ({})".format(str(ev.event), type(pkt)))
                    if pkt.predicates:
                        for pred in pkt.predicates:
                            try:
                                xfn = eval(pred)
                            except Exception as e:
                                log_warn("Couldn't eval the predicate ({}): {}".format(pred, str(e)))
            elif isinstance(ev.event, PacketInputTimeoutEvent):
                pass
            else:
                log_warn("Unrecognized event type in scenario event list: {}".format(str(type(ev.event))))

def get_scenario_object(sfile):
    '''
    Given a .py module containing a scenario object, import the module
    and return the object.  Raise an exception if anything goes wrong.

    (str) -> Scenario object
    '''
    try:
        mod = importlib.import_module(sfile.rstrip('.py'))
        sobj = getattr(mod, 'scenario')
        return sobj
    except ImportError as ie:
        raise SwitchyException("Couldn't import scenario file: {}".format(str(ie)))
    except AttributeError as ae:
        raise SwitchyException("Couldn't find required 'scenario' variable in your scenario file: {}".format(str(ae)))
    except Exception as e:
        raise SwitchyException("Error when getting scenario object: {}".format(str(e)))

def compile_scenario(scenario_file, output_filename=None):
    '''
    Compile a Switchy test scenario object to a serialized representation
    in a file for distribution.  Assumes that the input file is a .py
    module with a 'scenario' variable that refers to some Scenario object.

    (str/filename) -> str/filename
    '''
    sobj = get_scenario_object(scenario_file)
    sobj.scenario_sanity_check()
    outname = scenario_file.rstrip('.py') + '.switchy'
    pickle_repr = pickle.dumps(sobj)
    dig = hashlib.sha512()
    dig.update(pickle_repr)
    if output_filename:
        outname = output_filename
    xfile = open(outname, 'w')
    outstr = dig.digest() + pickle_repr
    xfile.write(base64.b64encode(bz2.compress(outstr)))
    xfile.close()
    return outname

def uncompile_scenario(scenario_file):
    '''
    Takes a serialized Scenario object stored in scenario_file and returns 
    the resurrected Scenario object.  Compares the sha512 hash embedded
    in the serialized object file with a newly computed hash to insure that
    the contents haven't been modified.

    (str/filename) -> Scenario object
    '''
    indata = open(scenario_file, 'rU').read()
    indata = base64.b64decode(indata.strip())
    indata = bz2.decompress(indata)
    dig = hashlib.sha512()
    digest = indata[:dig.digest_size]
    objrepr = indata[dig.digest_size:]
    dig.update(objrepr)
    if dig.digest() != digest:
        raise SwitchyException("Couldn't load scenario file (hash digest doesn't match)")
    sobj = pickle.loads(objrepr)
    return sobj

def get_test_scenario_from_file(sfile):
    '''
    Takes a file name as a parameter, which contains a 
    scenario object either in a .py module form, or serialized
    in a .switchy form.  

    (str/filename) -> Scenario object
    '''
    sobj = None
    if fnmatch.fnmatch(sfile, "*.py"):
        sobj = get_scenario_object(sfile)
    elif fnmatch.fnmatch(sfile, "*.switchy"):
        sobj = uncompile_scenario(sfile)
    else:
        sobj = get_scenario_object(sfile)
    return sobj

class FakePyLLNet(LLNetBase):
    '''
    A class that can used for testing code that uses PyLLNet.  Doesn't
    actually do any "real" network interaction; just manufactures
    packets of various sorts to test whether an IP router using this
    class behaves in what appear to be correct ways.
    '''    
    def __init__(self, scenario):
        LLNetBase.__init__(self)
        self.devinfo = scenario.interfaces()
        self.scenario = scenario
        self.timestamp = 0.0

    def shutdown(self):
        '''
        For FakePyLLNet, do nothing.
        '''
        pass

    def recv_packet(self, timeout=0.0, timestamp=False):
        '''
        Receive packets from any device on which one is available.
        Blocks until it receives a packet.  Returns None,None,None
        when device(s) are shut down (i.e., on a SIGINT to the process).

        Returns a tuple of device,timestamp,packet, where
            device: network device name on which packet was received
                    as a string
            timestamp: floating point value of time at which packet
                    was received
            packet: POX ethernet packet object
        '''
        # check if we're done with test scenario
        if self.scenario.done():
            raise Shutdown()
             
        ev = self.scenario.next()
        if ev.match(SwitchyTestEvent.EVENT_INPUT) == SwitchyTestEvent.MATCH_SUCCESS:
            self.scenario.testpass()
            return ev.generate_packet(timestamp, self.timestamp)
        else:
            self.scenario.testfail("recv_packet called, but I was expecting {}".format(str(ev)))
 
    def send_packet(self, devname, pkt):
        if self.scenario.done():
            raise ScenarioFailure("send_packet was called, but the scenario was finished.")
          
        ev = self.scenario.next()
        match_results = ev.match(SwitchyTestEvent.EVENT_OUTPUT, device=devname, packet=pkt)
        if match_results == SwitchyTestEvent.MATCH_SUCCESS:
            self.scenario.testpass()
        elif match_results == SwitchyTestEvent.MATCH_FAIL:
            self.scenario.testfail("send_packet was called, but I was expecting {}".format(str(ev)))
        else:
            # Not a pass or fail yet: means that we
            # are expecting more PacketOutputEvent objects before declaring
            # that the expectation matches/passes
            pass
        self.timestamp += 1.0          

def run_tests(scenario_names, usercode_entry_point, no_pdb, verbose):
    '''
    Given a list of scenario names, set up fake network object with the
    scenario objects, and invoke the user module.

    (list(str), function, bool, bool) -> None
    '''
    for sname in scenario_names:
        sobj = get_test_scenario_from_file(sname)
        net = FakePyLLNet(sobj)

        log_info("Starting test scenario {}".format(sname))
        exc = None
        message = '''All tests passed.  Now go try it in Mininet!'''
        try:
            usercode_entry_point(net)
        except Shutdown:
            pass
        except SwitchyException as exc:
            message = '''Your code crashed before I could run all the tests.'''
        except ScenarioFailure as exc:
            message = '''Your code didn't crash, but a test failed.'''
        except Exception as exc:
            message = '''Some kind of crash occurred before I could run all the tests.'''

        # there may be a pending SIGALRM for ensuring test completion;
        # turn it off.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)

        sobj.print_summary()

        # if we got an exception, print some contextual information
        # and dump the user into pdb to try to see what happened.
        if exc is not None:
            failurecontext = ''
            if sobj.get_failed_test() is not None:
                failurecontext = '\n'.join([' ' * 4 + s for s in textwrap.wrap(sobj.get_failed_test().description, 60)])
                failurecontext += '\n{}In particular:\n'.format(' ' * 4)
            failurecontext += '\n'.join([' ' * 8 + s for s in textwrap.wrap(str(exc), 60)]) 

            print >>sys.stderr,'''{}
{}
{}
{}

This is the Switchyard equivalent of the blue screen of death.  
Here (repeating what's above) is the failure that occurred:

{}    
'''.format(term_color('red'), '*'*60, message, '*'*60, failurecontext)

            if not verbose:
                message = "You can rerun with the -v flag to include full dumps of packets that may have caused errors. (By default, only relevant packet context may be shown, not the full contents.)"
                print textwrap.fill(message, 70)

            print reset_term_color()
            if no_pdb:
                print textwrap.fill("You asked not to be put into the Python debugger.  You got it.",70)
            else:
                print '''
I'm throwing you into the Python debugger (pdb) at the point of failure.
If you don't want pdb, use the --nopdb flag to avoid this fate.

    - Type "help" or "?" to get a list of valid debugger commands.
    - Type "exit" to get out.
    - Type "where" or "bt" to print a full stack trace.
    - You can use any valid Python commands to inspect variables
      for figuring out what happened.  

'''
                pdb.post_mortem()

        else:
            print >>sys.stderr,'{}{}'.format(term_color('green'), message)
            print reset_term_color()


def main_test(compile, scenarios, usercode, dryrun, no_pdb, verbose):
    '''
        Entrypoint function for either compiling or running test scenarios.

    (bool, list(str), str, bool, bool, bool) -> None
    '''
    if not scenarios or not len(scenarios):
        log_failure("In test mode, but no scenarios specified.")
        return

    if compile:
        for scenario in scenarios:
            log_info("Compiling scenario {}".format(scenario))
            compile_scenario(scenario)
    else:
        usercode_entry_point = import_user_code(usercode)
        if dryrun:
            log_info("Imported your code successfully.  Exiting dry run.")
            return
        run_tests(scenarios, usercode_entry_point, no_pdb, verbose)

def import_user_code(usercode):
    '''
    Import user code; return reference to usercode function.

    (str) -> function reference
    '''
    try:
        user_module = importlib.import_module(usercode.rstrip('.py'))
    except ImportError as e:
        log_failure("Couldn't import your module: {}".format(str(e)))
        sys.exit(-1)

    if USERMAIN not in dir(user_module):
        log_failure("Required entrypoint function {} not found in your code".format(USERMAIN))
        sys.exit(-1)

    return getattr(user_module, USERMAIN)

def main_real(usercode, dryrun, environment, includeintf, excludeintf):
    '''
    Entrypoint function for non-test ("real") mode.  At this point
    we assume that we are running as root and have pcap module.

    (str, bool, str, list(str), list(str)) -> None
    '''
    usercode_entry_point = import_user_code(usercode)
    if dryrun:
        log_info("Imported your code successfully.  Exiting dry run.")
        return
    net = PyLLNet(environment, includeintf, excludeintf)
    try:
        usercode_entry_point(net)
    except Exception as e:
        log_failure("Exception while running your code: {}".format(e))
        net.shutdown()

if __name__ == '__main__':
    progname = "switchy"
    parser = argparse.ArgumentParser(prog=progname)
    parser.add_argument("-t", "--test", help="Run {} in testing mode.".format(progname), dest="testmode", action="store_true", default=False)
    parser.add_argument("-e", "--environment", help="Run {} in a live environment.  Valid live environments are 'linux' and 'mininet'.  Default is 'mininet'.".format(progname), dest="environ", type=str, default="mininet", choices=['mininet', 'linux'])
    parser.add_argument("-i", "--include", metavar='INCLUDE_INTF', help="Specify interface names to include/use for data plane traffic (default: all non-loopback interfaces).", dest="intf", action='append')
    parser.add_argument("-x", "--exclude", metavar='EXCLUDE_INTF', help="Specify interface names to exclude in {}.  All other non-loopback interfaces will be used.".format(progname), dest="exclude", action='append')
    parser.add_argument("-c", "--compile", help="Compile scenario to binary format for distribution.", dest="compile", action="store_true", default=False)
    parser.add_argument("-s", "--scenario", help="Specify scenario file to use in test mode.", dest="scenario", action="append")
    parser.add_argument("--dryrun", help="Get everything ready to go, but don't actually do anything.", action='store_true', dest='dryrun', default=False)
    parser.add_argument("-v", "--verbose", help="Turn on verbose output, including full packet dumps in test results.  Can be specified multiple times to increase verbosity.", dest="verbose", action="count", default=0)
    parser.add_argument("-d", "--debug", help="Turn on debug logging output.", dest="debug", action="store_true", default=False)
    parser.add_argument("--nopdb", help="Don't enter pdb on crash.", dest="nopdb", action="store_true", default=False)
    parser.add_argument('usercode', metavar="YOURCODE", type=str, nargs='?', help='User switch/router code to execute.')
    args = parser.parse_args()

    # assume test mode if the compile flag is set
    if args.compile:
        args.testmode = True

    if args.verbose:
        PacketFormatter.full_display()

    setup_logging(args.debug)

    if args.usercode is None and not args.compile:
        log_failure("You need to specify the name of your module to run as the last argument")
        sys.exit()

    try:
        import pox
    except ImportError as e:
        log_failure("Error importing required module POX.  Run ./setup.sh")
        sys.exit(-1)

    if args.testmode:
        if args.usercode and args.compile:
            log_info("You specified user code to run with compile flag, but I'm just doing compile.")
        main_test(args.compile, args.scenario, args.usercode, args.dryrun, args.nopdb, args.verbose)
    else:
        if args.environ not in ['linux', 'mininet']:
            log_failure("Runtime environment {} is not valid.  'linux' and 'mininet' are the only valid environments, currently".format(args.environ))
            sys.exit(-1)

        try:
            import pcap
        except ImportError as e:
            print '''{}
Error importing pcap module.  Did you mean to specify --test 
to run in test mode?  If not, you need to install the pcap 
module before continuing or correctly set PYTHONPATH.'''.format(term_color('red'))
            sys.exit(-1)
        if os.getuid() != 0:
            print '''
{}You're running in real mode, but not as root.  You should 
expect errors, but I'm going to continue anyway.{}'''.format(term_color('blue'), reset_term_color())
        
        if args.exclude is None:
            args.exclude = []
        if args.intf is None:
            args.intf = []
        main_real(args.usercode, args.dryrun, args.environ, args.intf, args.exclude)
