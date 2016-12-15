import sys
import argparse
import os
import signal
import re
import subprocess
import time
from queue import Queue,Empty
import importlib
import bz2
import hashlib
import pickle
import base64
import fnmatch
import copy
import textwrap
from collections import namedtuple, defaultdict
from abc import ABCMeta, abstractmethod

from .packet import *
from .address import *
from .interface import Interface
from .exceptions import *
from .logging import log_debug
from . import debugging as sdebug
from ..textcolor import *
from ..importcode import import_or_die
from ..llnetbase import ReceivedPacket

class PacketFormatter(object):
    _fulldisp = False

    @staticmethod
    def full_display(value=True):
        PacketFormatter._fulldisp = value

    @staticmethod
    def format_pkt(pkt, cls=None):
        '''
        Return a string representation of a packet.  If display_class is a known
        header type, just show the string repr of that header.  Otherwise, dump
        the whole thing.
        '''
        if PacketFormatter._fulldisp:
            cls = None

        if cls is None:
            return str(pkt)
        idx = pkt.get_header_index(cls)
        if idx == -1:
            log_warn("PacketFormatter tried to find non-existent header {} (test scenario probably needs fixing)".format(str(cls)))
            return str(pkt)
        return ' | '.join([str(pkt[i]) for i in range(idx, pkt.num_headers())])


class SwitchyTestEvent(object):
    MATCH_FAIL = 0x00
    MATCH_SUCCESS = 0x01
    MATCH_PARTIAL = 0x02

    EVENT_INPUT = 0x10
    EVENT_OUTPUT = 0x20

    __metaclass__ = ABCMeta
    def __init__(self):
        self._display = None

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
        return PacketFormatter.format_pkt(pkt, self._display)


class AbstractMatch(metaclass=ABCMeta):
    @abstractmethod
    def match(self, pkt):
        return False

    @abstractmethod
    def show(self, comparepkt):
        pass


class ExactMatch(AbstractMatch):
    def __init__(self, pkt):
        self._reference = pkt.to_bytes()

    def match(self, pkt):
        return self._reference == pkt.to_bytes()

    def __str__(self):
        return str(Packet(raw=self._reference))

    def show(self, comparepkt):
        return str(self)


class WildcardMatchOpenflow(AbstractMatch):
    ETHWILD = '**:**:**:**:**:**'
    SINGLE = '*'
    IP4WILD = '*.*.*.*'
    IP6WILD = '**::**'
    _ETHFMT = ("{} {}->{} {}", 'dl_src', 'dl_dst', 'dl_type')
    _IPFMT = ("{} {}->{} {}", 'nw_src', 'nw_dst', 'nw_proto')
    _ARPFMT = ("{} {}:{} {}:{}", 'arp_sha', 'arp_spa', 'arp_tha', 'arp_tpa')
    _TPORTFMT = ("{} {}->{}", 'tp_src', 'tp_dst')
    _SHOWORDER = [(Ethernet, _ETHFMT), (Arp, _ARPFMT),
                  (IPv4, _IPFMT), (IPv6, _IPFMT),
                  (TCP, _TPORTFMT), (UDP, _TPORTFMT), (ICMP, _TPORTFMT)]

    _LOOKUP = {
        'dl_src': [(Ethernet, 'src', ETHWILD)],
        'dl_dst': [(Ethernet, 'dst', ETHWILD)],
        'dl_type': [(Ethernet, 'ethertype', SINGLE)],
        'nw_src': [(IPv4, 'src', IP4WILD), (IPv6, 'src', IP6WILD)],
        'nw_dst': [(IPv4, 'dst', IP4WILD), (IPv6, 'dst', IP6WILD)],
        'nw_proto': [(IPv4, 'protocol', SINGLE), (IPv6, 'protocol', SINGLE)],
        'tp_src': [(TCP, 'src', SINGLE), (UDP, 'src', SINGLE), (ICMP, 'icmptype', SINGLE)],
        'tp_dst': [(TCP, 'dst', SINGLE), (UDP, 'dst', SINGLE), (ICMP, 'icmpcode', SINGLE)],
        'arp_tpa': [(Arp, 'targetprotoaddr', IP4WILD)],
        'arp_spa': [(Arp, 'senderprotoaddr', IP4WILD)],
        'arp_tha': [(Arp, 'targethwaddr', ETHWILD)],
        'arp_sha': [(Arp, 'senderhwaddr', ETHWILD)],
    }
    _BYHEADER = None

    def __init__(self, pkt, wildcard_fields):
        if WildcardMatchOpenflow._BYHEADER is None:
            WildcardMatchOpenflow._BYHEADER = defaultdict(list)
            for xkey, xlist in WildcardMatchOpenflow._LOOKUP.items():
                for cls, headerfield, wildfmt in xlist:
                    WildcardMatchOpenflow._BYHEADER[cls].append(xkey)
        if not isinstance(wildcard_fields, (tuple,list)):
            raise ValueError("Wildcard fields should be given as a list or tuple,"
                " but you gave a {}".format(type(wildcard_fields)))
        self._wildcards = tuple(wildcard_fields)
        self._matchvals = self._buildmvals(pkt)

    def _buildmvals(self, pkt):
        mvals = {}
        for key,llist in WildcardMatchOpenflow._LOOKUP.items():

            # only build a comparison table of fields that aren't
            # listed in wildcards
            if key in self._wildcards:
                continue

            for cls,field,_ in llist:
                if pkt.has_header(cls):
                    header = pkt.get_header(cls)
                    value = getattr(header,field)
                    mvals[key] = value
        return mvals

    def match(self, pkt):
        mvals = self._buildmvals(pkt)
        return mvals == self._matchvals

    def __str__(self):
        return 'Wildcarded fields: {}'.format(' '.join(self._wildcards))

    def __getstate__(self):
        d = self.__dict__.copy()
        return d

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)

    def __getattr__(self, attr):
        if attr in self._matchvals:
            return self._matchvals[attr]
        raise AttributeError("No such attribute {}".format(attr))

    def show(self, comparepkt):
        def fill_field(field, header):
            for clsname,attr,wilddisplay in WildcardMatchOpenflow._LOOKUP[field]:
                if isinstance(header, clsname):
                    if field in self._wildcards:
                        return wilddisplay
                    elif hasattr(header, attr):
                        a = getattr(header, attr)
                        if isinstance(a, Enum):
                            return str(a.name)
                        return str(a)
                    return wilddisplay
            raise Exception("Should never get here!")

        def with_wildcards(header, fmt):
            args = [header.__class__.__name__]
            args.extend([fill_field(field, header) for field in fmt[1:]])
            return fmt[0].format(*args)

        headers = []
        for clsname, fmt in WildcardMatchOpenflow._SHOWORDER:
            if comparepkt.has_header(clsname):
                headers.append(with_wildcards(comparepkt.get_header(clsname), fmt))
        return ' | '.join(headers)


class WildcardMatchClassAttr(AbstractMatch):
    def __init__(self, pkt, wildcard_fields):
        self._pkt = self._rewrite_fields(pkt, wildcard_fields)
        self._wildcards = wildcard_fields

    @staticmethod
    def _rewrite_fields(pkt, fields):
        def star_out_attr(hdr, attr):
            attrpriv = "_" + attr
            if not hasattr(hdr, attr):
                return
            oldattr = getattr(hdr, attr)
            newattr = '*'
            if isinstance(oldattr, IPv4Address):
                newattr = '*.*.*.*'
            elif isinstance(oldattr, IPv6Address):
                newattr = '*::*'
            elif isinstance(oldattr, EthAddr):
                newattr = '**:**:**:**:**:**'
            setattr(hdr, attrpriv, newattr)

        pktcopy = copy.deepcopy(pkt)
        for klass,attr in fields:
            header = pktcopy.get_header(klass)
            if header is not None:
                star_out_attr(header, attr)
        return pktcopy

    def match(self, comparepkt):
        cpkt = self._rewrite_fields(comparepkt, self._wildcards)
        return self._pkt == cpkt    

    def show(self, comparepkt):
        cpkt = self._rewrite_fields(comparepkt, self._wildcards)
        return str(cpkt)


class WildcardMatch(AbstractMatch):
    def __init__(self, pkt, wildcard_fields):
        if not isinstance(wildcard_fields, (tuple,list)):
            raise ValueError("Wildcard fields should be given as a list or tuple,"
                " but you gave a {}".format(type(wildcard_fields)))
        self._delegate = None
        if not len(wildcard_fields) or isinstance(wildcard_fields[0], str):
            self._delegate = WildcardMatchOpenflow(pkt, wildcard_fields)
        elif isinstance(wildcard_fields[0], (tuple,list)):
            self._delegate = WildcardMatchClassAttr(pkt, wildcard_fields)
        else:
            raise ValueError("Wildcard fields can either be strings naming "
                "fields in the style of Openflow 1.0, or as (class,attr) "
                "elements.  You didn't appear to give me either.")

    def match(self, comparepkt):
        return self._delegate.match(comparepkt)

    def __str__(self):
        return str(self._delegate)

    def show(self, comparepkt):
        return self._delegate.show(comparepkt)


class PacketMatcher(object):
    '''
    Class whose job it is to define a packet template against which
    some other packet is matched, particularly for PacketOutputEvents,
    where we want to verify that a packet emitted by Switchyard app code
    conforms to some expectation.  This class delegates some of the
    matching work to the WildcardMatch class.
    '''
    def __init__(self, packet, *predicates, **kwargs):
        '''
        Instantiate the matcher delegate.  template is expected
        to be a Packet object.

        An arbitrary number of predicate functions can also be
        passed.  Each predicate function must be defined as a
        string with a single lambda.  Each lambda must take
        a single arg (a Packet object) and return bool.

        Recognized kwargs: exact and wildcard

        exact determines whether a byte-by-byte comparison is done
        against a reference packet, or a more flexible match is done
        based on the fields available in an openflow flow table entry.

        wildcard is a list of strings that must match fields in the
        WildcardMatch structure.  this is only used if exact=False, and
        the effect is to wildcard those fields in the WildcardMatch.
        Fields: dl_src, dl_dst, dl_type, dl_vlan, dl_vlan_pcp,
        nw_src, nw_dst, nw_proto, nw_tos, tp_src, tp_dst,
        arp_tpa, arp_spa, arp_tha, arp_sha
        '''
        wildcard = []
        if 'wildcard' in kwargs:
            wildcard = kwargs.pop('wildcard')

        self._exact = False
        if 'exact' in kwargs:
            self._exact = bool(kwargs.pop('exact'))
            if self._exact and len(wildcard):
                log_warn("Wildcards given but exact match specified. "
                         "Ignoring exact match.")
                self._exact = False
        elif not wildcard:
            # if no wildcards given, default to exact match
            self._exact = True

        if len(kwargs):
            log_warn("Ignoring unrecognized keyword arguments for building output packet matcher: {}".format(kwargs))

        if self._exact:
            self._matchobj = ExactMatch(packet)
        else:
            self._matchobj = WildcardMatch(packet, wildcard)

        self._packet = packet
        self._first_header = None
        if len(self._packet):
            self._first_header = packet[0].__class__

        self._predicates = []
        if len(predicates) > 0:
            boguslambda = lambda: 0
            for i in range(len(predicates)):
                if not isinstance(predicates[i], str):
                    raise Exception("Predicates used for matching packets must be strings (in the form of a lambda definition)")
                try:
                    fn = eval(predicates[i])
                except SyntaxError:
                    raise SyntaxError("Predicate strings passed to PacketMatcher must conform to Python lambda syntax")
                if type(boguslambda) != type(fn):                    
                    raise Exception("Predicate was not a lambda expression: {}".format(predicate[i]))
                self._predicates.append(predicates[i])

    @property
    def packet(self):
        return self._packet

    def _diagnose(self, packet, results):
        '''
        Construct/return a string that describes why a packet doesn't
        match this matcher.
        '''
        firstmatch = results.pop(0)
        xtype = "exact" if self._exact else "wildcard"
        aan = 'an' if xtype == 'exact' else 'a'
        xresults = "passed" if firstmatch else "failed"
        conjunction = ', but' if firstmatch else '. '
        diagnosis = ["{} {} match {}{}".format(aan.capitalize(), xtype, xresults, conjunction)]

        # are there predicates that were tested?
        if len(results):
            diagnosis += ["when comparing the packet you sent versus what I expected,"]
            # if previous statement ended with sentence, cap the last
            # statement added.
            if diagnosis[-2].endswith('.'):
                diagnosis[-1] = diagnosis[-1].capitalize()

            for pidx,preresult in enumerate(results):
                xresults = "passed" if preresult else "failed"
                xname = self._predicates[pidx]
                conjunction = 'and' if pidx == len(results)-1 else ''
                diagnosis += ["{} the predicate ({}) {}".format(conjunction, xname, xresults)]
                if not conjunction:
                    diagnosis[-1] += ','
            diagnosis[-1] += '.'

        if firstmatch: 
            # headers match, but predicate(s) failed
            diagnosis += ["\nThis part matched: {}.".format(self._matchobj.show(packet))]
        else:
            # packet header match failed
            diagnosis += ["\nHere is the packet that failed the check: {}.".format(packet)]

            if self._exact:
                diagnosis += ["\nHere is exactly what I expected: {}.".format(self._matchobj.show(packet))]
            else:
                diagnosis += ["\nHere is what I expected to match: {}.".format(self._matchobj.show(packet))]
        return ' '.join(diagnosis)

    def match(self, packet):
        '''
        Determine whether packet matches our expectation.
        The packet is only a match if it meets WildcardMatch
        criteria, and all predicates return True.
        If no match, then construct a "nice" description
            of what doesn't match, and throw an exception.
        '''
        results = [ self._matchobj.match(packet) ]
        results += [ eval(fn)(packet) for fn in self._predicates ]
        if all(results):
            return True
        else:
            raise TestScenarioFailure(self._diagnose(packet, results))

    def __getstate__(self):
        rv = self.__dict__.copy()
        rv['_packet'] = rv['_packet'].to_bytes()
        return rv

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)
        self._packet = Packet(raw=self._packet, first_header=self._first_header)

class PacketInputTimeoutEvent(SwitchyTestEvent):
    '''
    Test event that models a timeout when trying to receive
    a packet.  No packet arrives, so the switchy app should
    handle a NoPackets exception and continue
    '''
    def __init__(self, timeout):
        self._timeout = timeout

    def __getstate__(self):
        return self.__dict__.copy()

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)

    def __eq__(self, other):
        return isinstance(other, PacketInputTimeoutEvent) and \
            self._timeout == other._timeout

    def __str__(self):
        return "Timeout {}s on recv_packet".format(self._timeout)

    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketInputEvent currently ignores
        any additional arguments.
        '''
        if evtype == SwitchyTestEvent.EVENT_INPUT:
            return SwitchyTestEvent.MATCH_SUCCESS
        else:
            return SwitchyTestEvent.MATCH_FAIL

    def generate_packet(self, timestamp, scenario):
        time.sleep(self._timeout)
        raise NoPackets()


class PacketInputEvent(SwitchyTestEvent):
    '''
    Test event that models a packet arriving at a router/switch
    (e.g., a packet that we generate).
    '''
    def __init__(self, device, packet, display=None, copyfromlastout=None):
        self._device = device
        self._packet = packet
        if packet.num_headers() > 0:
            self._first_header = packet[0].__class__ 
        else:
            self._first_header = None
        self._display = display
        self._copyfromlastout = copyfromlastout

    def __getstate__(self):
        rv = self.__dict__.copy()
        rv['_packet'] = self._packet.to_bytes()
        return rv

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)
        self._packet = Packet(raw=self._packet, first_header=self._first_header)

    def __eq__(self, other):
        return isinstance(other, PacketInputEvent) and \
            self._device == other._device and \
            str(self._packet) == str(other._packet)

    def __str__(self):
        return "recv_packet {} on {}".format(self.format_pkt(self._packet), self._device)

    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketInputEvent currently ignores
        any additional arguments.
        '''
        if evtype == SwitchyTestEvent.EVENT_INPUT:
            return SwitchyTestEvent.MATCH_SUCCESS
        else:
            return SwitchyTestEvent.MATCH_FAIL

    def generate_packet(self, timestamp, scenario):
        # ensure that the packet is fully parsed before
        # delivering it.  cost is immaterial since this
        # is just testing code!
        self._packet = Packet(raw=self._packet.to_bytes(), first_header=self._first_header)
        if self._copyfromlastout:
            intf,outcls,outprop,incls,inprop = self._copyfromlastout
            hdrval = scenario.lastout(intf, outcls, outprop)
            hdr = self._packet.get_header(incls)
            setattr(hdr, inprop, hdrval)
        return ReceivedPacket(timestamp=timestamp, input_port=self._device, packet=self._packet)


class PacketOutputEvent(SwitchyTestEvent):
    '''
    Test event that models a packet that should be emitted by
    a router/switch.
    '''
    def __init__(self, *args, **kwargs):
        self._matches = {}
        self._device_packet_map = {}
        self._display = None
        if 'display' in kwargs:
            self._display = kwargs.pop('display')
        predicates = []
        if 'predicates' in kwargs:
            predicates = kwargs.pop('predicates')

        if len(args) == 0:
            raise Exception("PacketOutputEvent expects a list of device1, pkt1, device2, pkt2, etc., but no arguments were given.")
        if len(args) % 2 != 0:
            raise Exception("Arg list length to PacketOutputEvent must be even (device1, pkt1, device2, pkt2, etc.)")
        for i in range(0, len(args), 2):
            matcher = PacketMatcher(args[i+1], *predicates, **kwargs)
            self._device_packet_map[args[i]] = matcher

    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketOutputEvent requires
        two additional keyword args: device (str) and packet (packet object).
        '''
        if evtype != SwitchyTestEvent.EVENT_OUTPUT:
            return SwitchyTestEvent.MATCH_FAIL
        if 'device' not in kwargs or 'packet' not in kwargs:
            return SwitchyTestEvent.MATCH_FAIL
        device = kwargs['device']
        pkt = kwargs['packet']

        if device in self._device_packet_map:
            matcher = self._device_packet_map[device]
            if matcher.match(pkt):
                self._matches[device] = pkt
                del self._device_packet_map[device]
                if len(self._device_packet_map) == 0:
                    return SwitchyTestEvent.MATCH_SUCCESS
                else:
                    return SwitchyTestEvent.MATCH_PARTIAL
            else:
                raise TestScenarioFailure("test failed when you called send_packet: output device {} is ok, but\n\t{}\n\tdoesn't match what I expected\n\t{}".format(device, self.format_pkt(pkt, self._display), matcher.show(self._display)))
        else:
            raise TestScenarioFailure("test failed when you called send_packet: output on device {} unexpected (I expected this: {})".format(device, str(self)))

    @property
    def matches(self):
        return self._matches

    def __str__(self):
        s = "send_packet(s) "
        # in device_packet_map, values are Match objects
        devlist = ["{} out {}".format(self.format_pkt(v.packet),k) for k,v in self._device_packet_map.items() ]
        # in matches, values are packets
        devlist += ["{} out {}".format(self.format_pkt(v),k) for k,v in self._matches.items() ]
        s += ' and '.join(devlist)
        return s

    def __getstate__(self):
        rv = self.__dict__.copy()
        for dev in rv['_matches']:
            pkt = rv['_matches'][dev].to_bytes()
            rv['_matches'][dev] = pkt
        return rv

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)
        for dev in self._matches:
            raw = self._matches[dev]
            pkt = Packet(raw=raw)
            self._matches[dev] = pkt

    def __eq__(self, other):
        return isinstance(other, PacketOutputEvent) and \
            str(self) == str(other)


TestScenarioEvent = namedtuple('TestScenarioEvent', ['event','description','timestamp'])

class TestScenario(object):
    '''
    Test scenario definition.  Given a list of packetio event objects,
    generates input events and tests/verifies output events.
    '''
    def __init__(self, name):
        self._interface_map = {}
        self._name = name
        self._pending_events = []
        self._completed_events = []
        self._timer = False
        self._next_timestamp = 0.0
        self._timeoutval = 60
        self._support_files = {}
        self._setup = None
        self._teardown = None
        self._lastout = None

    @property  
    def name(self):
        return self._name

    @property
    def timeout(self):
        return self._timeoutval

    @timeout.setter
    def timeout(self, value):
        self._timeoutval = int(value)

    def lastout(self, intf, header, property):
        if self._lastout is not None:
            pkt = self._lastout.get(intf, None)
            if pkt is not None:
                hdr = pkt.get_header(header)
                return getattr(hdr, property)

    def add_file(self, fname, text):
        self._support_files[fname] = text

    def write_files(self):
        for fname, text in self._support_files.items():
            with open(fname, 'w') as outfile:
                outfile.write(text)

    @property 
    def setup(self):
        return self._setup 

    @setup.setter
    def setup(self, value):
        self._setup = value

    def do_setup(self):
        if self._setup:
            self._setup()

    @property
    def teardown(self):
        return self._teardown

    @teardown.setter
    def teardown(self, value):
        self._teardown = value

    def do_teardown(self):
        if self._teardown:
            self._teardown()

    def add_interface(self, interface_name, macaddr, ipaddr=None, netmask=None, **kwargs):
        '''
        Add an interface to the test scenario.

        (str, str/EthAddr, str/IPAddr, str/IPAddr) -> None
        '''
        if 'ifnum' not in kwargs:
            kwargs['ifnum'] = len(self._interface_map)
        if ipaddr is not None:
            kwargs['ipaddr'] = ipaddr
        if netmask is not None:
            kwargs['netmask'] = netmask
        intf = Interface(interface_name, macaddr, **kwargs)
        self._interface_map[interface_name] = intf

    def interfaces(self):
        return self._interface_map

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
        self._pending_events.append( TestScenarioEvent(event, description, self._next_timestamp) )
        self._next_timestamp += 1.0

    def get_failed_test(self):
        '''
        Return the head of the pending_events queue.  In the case of failure,
        this is the expectation that wasn't met.
        '''
        if self._pending_events:
            return self._pending_events[0]
        return None

    def next(self):
        '''
        Return the next expected event to happen.
        '''
        if not self._pending_events:
            raise TestScenarioFailure("next() called on scenario '{}', but not expecting anything else for this scenario".format(self.name))
        else:
            return self._pending_events[0].event

    def testfail(self, message):
        '''
        Method to call if the current expected event does not
        occur, i.e., the test expectation wasn't met.
        '''
        raise TestScenarioFailure("{}".format(message))

    def _timer_expiry(self, signum, stackframe):
        '''
        Callback method for ensuring that send_packet gets called appropriately
        from user code (i.e., code getting tested).
        '''
        if sdebug.in_debugger:
            self._timer = False
            return

        if self._timer:
            log_debug("Timer expiration while expecting PacketOutputEvent")
            raise TestScenarioFailure("Expected send_packet to be called to match {} in scenario {}, but it wasn't called, and after {} seconds I gave up.".format(str(self._pending_events[0]), self.name, self.timeout))
        else:
            log_debug("Ignoring timer expiry with timer=False")

    def cancel_timer(self):
        '''
        Don't let any pending SIGALRM interrupt things.
        '''
        self._timer=False

    def testpass(self):
        '''
        Method to call if the current expected event occurs, i.e., an event
        expectation has been met.

        Move current event (head of pending list) to completed list and disable
        any timers that may have been started.
        '''
        self._timer = False
        ev = self._pending_events.pop(0)
        log_debug("Test pass: {} - {}".format(ev.description, str(ev.event)))
        self._completed_events.append(ev)

        if isinstance(ev.event, PacketOutputEvent):
            self._lastout = ev.event.matches

        if not len(self._pending_events):
            return

        # if head of expected is pktout, set alarm for 1 sec
        # or so to check that we actually receive a packet.
        if isinstance(self._pending_events[0].event, PacketOutputEvent):
            log_debug("Setting timer for next PacketOutputEvent")
            signal.alarm(self.timeout)
            signal.signal(signal.SIGALRM, self._timer_expiry)
            self._timer = True

        log_debug("Next event expected: "+str(self._pending_events[0].event))

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
        with blue():
            print ("\nResults for test scenario {}:".format(self.name), end='')
            print ("{} passed, {} failed, {} pending".format(len(self._completed_events), min(1,len(self._pending_events)), max(0,len(self._pending_events)-1)))

        if len(self._completed_events):
            with green():
                print ("\nPassed:")
                for idx,ev in enumerate(self._completed_events):
                    idxstr = str(idx+1)
                    print ("{}{}".format(idxstr, self.wrapevent(ev.description, str(ev.event))[len(idxstr):]))

        if len(self._pending_events):
            with red():
                print ("\nFailed:")
                failed_event = self._pending_events[0]
                print ("{}".format(self.wrapevent(failed_event.description, str(failed_event.event))))
            if len(self._pending_events) > 1:
                with yellow():
                    print ("\nPending (couldn't test because of prior failure):")
                    for idx,ev in enumerate(self._pending_events[1:]):
                        idxstr = str(idx+1)
                        print ("{}{}".format(idxstr, self.wrapevent(ev.description, str(ev.event))[len(idxstr):]))
        print()

    def done(self):
        '''
        Boolean method that tests whether the test scenario
        is done or not.
        '''
        return len(self._pending_events) == 0

    def __str__(self):
        return "scenario {}".format(self.name)

    def __getstate__(self):
        odict = self.__dict__.copy()
        del odict['_timer']
        odict['_events'] = odict['_pending_events'] + odict['_completed_events']
        del odict['_pending_events']
        del odict['_completed_events']
        del odict['_setup']
        del odict['_teardown']
        return odict

    def __setstate__(self, xdict):
        xdict['_pending_events'] = xdict['_events']
        del xdict['_events']
        xdict['_timer'] = None
        xdict['_completed_events'] = []
        xdict['_setup'] = None
        xdict['_teardown'] = None
        self.__dict__.update(xdict)

    def __eq__(self, other):
        if not isinstance(other, TestScenario):
            return False
        if self._next_timestamp != other._next_timestamp:
            return False
        selfev = self._pending_events + self._completed_events
        otherev = other._pending_events + other._completed_events
        if len(selfev) != len(otherev):
            return False
        for i in range(len(selfev)):
            if selfev[i] != otherev[i]:
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
        for ev in self._pending_events:
            if isinstance(ev.event, PacketInputEvent):
                if ev.event._device not in self._interface_map:
                    log_warn("PacketInputEvent ({}) refers to a device not part of scenario interface map".format(str(ev.event)))
                if not isinstance(ev.event._packet, Packet):
                    log_warn("PacketInputEvent ({}) refers to a non-packet object ({})".format(str(ev.event), type(ev.event._packet)))
            elif isinstance(ev.event, PacketOutputEvent):
                if not len(ev.event._device_packet_map):
                    log_warn("PacketOutputEvent ({}) doesn't have any output devices included".format(ev.event))
                for dev,pkt in ev.event._device_packet_map.items():
                    if dev not in self._interface_map:
                        log_warn("PacketOutputEvent () refers to a device not part of scenario interface map".format(str(ev.event)))
                    if not isinstance(pkt, PacketMatcher):
                        log_warn("PacketOutputEvent ({}) refers to a non-PacketMatcher object ({})".format(str(ev.event), type(pkt)))
                    if pkt._predicates:
                        for pred in pkt._predicates:
                            try:
                                xfn = eval(pred)
                            except Exception as e:
                                log_warn("Couldn't eval the predicate ({}): {}".format(pred, str(e)))
            elif isinstance(ev.event, PacketInputTimeoutEvent):
                pass
            else:
                log_warn("Unrecognized event type in scenario event list: {}".format(str(type(ev.event))))

def compile_scenario(scenario_file, output_filename=None):
    '''
    Compile a Switchy test scenario object to a serialized representation
    in a file for distribution.  Assumes that the input file is a .py
    module with a 'scenario' variable that refers to some Scenario object.

    (str/filename) -> str/filename
    '''
    sobj = import_or_die(scenario_file, ('scenario',))
    sobj.scenario_sanity_check()
    outname = scenario_file.rstrip('.py') + '.srpy'
    pickle_repr = pickle.dumps(sobj, pickle.HIGHEST_PROTOCOL)
    dig = hashlib.sha512()
    dig.update(pickle_repr)
    if output_filename:
        outname = output_filename
    xfile = open(outname, 'w')
    outstr = dig.digest() + pickle_repr
    xfile.write(base64.b64encode(bz2.compress(outstr)).decode('ascii'))
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
    with open(scenario_file, 'r') as infile:
        indata = infile.read()
    indata = base64.b64decode(indata.strip())
    indata = bz2.decompress(indata)
    dig = hashlib.sha512()
    digest = indata[:dig.digest_size]
    objrepr = indata[dig.digest_size:]
    dig.update(objrepr)
    if dig.digest() != digest:
        raise ValueError("Couldn't load scenario file (hash digest doesn't match)")
    sobj = pickle.loads(objrepr)
    return sobj

def get_test_scenario_from_file(sfile):
    '''
    Takes a file name as a parameter, which contains a
    scenario object either in a .py module form, or serialized
    in a .srpy form.

    (str/filename) -> Scenario object
    '''
    sobj = None
    if fnmatch.fnmatch(sfile, "*.py"):
        sobj = import_or_die(sfile, ('scenario',))
    elif fnmatch.fnmatch(sfile, "*.srpy"):
        sobj = uncompile_scenario(sfile)
    else:
        sobj = import_or_die(sfile, ('scenario',))
    return sobj
