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
from copy import deepcopy
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
from ..outputfmt import VerboseOutput


class TestScenarioFailure(SwitchyardException):
    '''An exception that is raised when a TestScenario expectation
    is not met.'''
    pass


class _PacketMatcher(object):
    '''
    Class whose job it is to define a packet template against which
    some other packet is matched, particularly for PacketOutputEvents,
    where we want to verify that a packet emitted by Switchyard app code
    conforms to some expectation.  
    '''
    def __init__(self, packet, predicates=[], wildcards=[], **kwargs):
        '''
        Instantiate the matcher delegate.  template is expected
        to be a Packet object.

        An arbitrary number of predicate functions can also be
        passed as a list to the kwarg predicates.  Each predicate 
        function must be defined as a string with a single lambda.  
        Each lambda must take a single arg (a Packet object) and 
        return bool.

        wildcards is a list (or tuple) of either (1) strings that refer
        to particular header attributes that should not be compared (the
        strings are borrowed from the Openflow 1.0 spec), or (2) a 2-tuple
        or 2-list composed of a header class name and an attribute.  
        The second method of wildcarding is preferred and the first is
        deprecated.  The ability to specify Openflow-like attributes
        to wildcard will be removed from a future version.

        Recognized kwargs: exact.
          exact determines whether a byte-by-byte comparison is done
          against a reference packet, or a more limited set of attributes
          is used for comparison.  

          The default is exact=True, i.e., all attributes are compared.

        NB: both wildcards and exact can be reasonably used together.
        exact=False simply means that fewer attributes are used by default
        (e.g., addresses, protocol numbers, etc.).  Wildcarding can be used
        to compare against even fewer fields.  If exact=True, *all* attributes
        are compared except for those that are explicitly wildcarded.
        '''
        self._exact = kwargs.pop('exact', True)
        self._reference_packet = deepcopy(packet)
        self._wildcards = self._check_wildcards(wildcards)
        self._predicates = self._check_predicates(predicates)
        self._compute_comparison_attrs(packet, self._exact, self._wildcards)
        if len(kwargs):
            log_warn("Ignoring unrecognized keyword arguments for building output packet matcher: {}".format(kwargs))
        self._first_header = None
        if len(self._reference_packet):
            self._first_header = self._reference_packet[0].__class__
        self._lastresults = None

    @property
    def packet(self):
        return self._reference_packet

    @staticmethod
    def _check_predicates(predicates):
        pred = []
        if len(predicates) > 0:
            boguslambda = lambda: 0
            for i in range(len(predicates)):
                if not isinstance(predicates[i], str):
                    raise Exception("Predicates used for matching packets must be strings (in the form of a lambda definition)")
                try:
                    fn = eval(predicates[i])
                except SyntaxError:
                    raise SyntaxError("Predicate strings must conform to Python lambda syntax")
                if type(boguslambda) != type(fn):                    
                    raise Exception("Predicate was not a lambda expression: {}".format(predicate[i]))
                pred.append(predicates[i])
        return pred

    @staticmethod
    def _check_wildcards(wildcards):
        if not isinstance(wildcards, list):
            raise TypeError("wildcards must be in a list")
        for wc in wildcards:
            if not isinstance(wc, (list,tuple)) or len(wc) != 2:
                raise ValueError("Each wildcard must be a list or tuple of length 2")
            wcklass,wcattr = wc[0],wc[1]
            if not issubclass(wcklass, PacketHeaderBase):
                raise ValueError("First element in a wildcard must be the name of a packet header class")
            if not (isinstance(wcattr, str) and hasattr(wcklass, wcattr)):
                raise ValueError("Wildcard pair must be a valid packet header class and attribute on that class")
        return wildcards

    def _compute_comparison_attrs(self, pkt, exact, wildcards):
        def _collect_header_attrs(pkthdr):
            attrlist = []
            for attr in dir(pkthdr):
                if attr.startswith('_') or attr == 'checksum':
                    continue
                aval = getattr(pkthdr, attr)
                if callable(aval):
                    continue
                attrlist.append(attr)
            return attrlist

        def _collect_all_attrs(pkt):
            attrhash = {}
            for hdr in pkt:
                hdrcls = hdr.__class__
                attrhash[hdrcls] = _collect_header_attrs(hdr)
            return attrhash

        def _compute_inexact(pkt):
            _inexact_comparison_attributes = {
                Ethernet: ['src', 'dst', 'ethertype'],
                Arp: ['targetprotoaddr', 'senderprotoaddr', 'targethwaddr', 'senderhwaddr'],
                IPv4: ['src', 'dst', 'protocol'],
                IPv6: ['src', 'dst', 'nextheader'],
                TCP: ['src', 'dst'],
                UDP: ['src', 'dst'],
                ICMP: ['icmptype', 'icmpcode'],
                ICMPv6: ['icmptype', 'icmpcode'],
                Vlan: ['vlanid', 'ethertype'],
            }
            attrhash = deepcopy(_inexact_comparison_attributes)
            foundclasses = set([ hdr.__class__ for hdr in pkt ])
            # remove classes/keys from attrhash if there aren't 
            # corresponding headers in the pkt
            for hdrcls in list(_inexact_comparison_attributes.keys()):
                if hdrcls not in foundclasses:
                    del attrhash[hdrcls]
            return attrhash

        def _filter_wildcards():
            for klass,attr in self._wildcards:
                attrlist = self._comparison_attrs.get(klass, [])
                if attr in attrlist:
                    attrlist.remove(attr)

        if exact:
            self._comparison_attrs = _collect_all_attrs(pkt)
        else:
            self._comparison_attrs = _compute_inexact(pkt)
        _filter_wildcards()

    def _compare_packet_against_reference(self, packet):
        def _compare_header_types(packet):
            i = 0
            while i < packet.num_headers() and i < self._reference_packet.num_headers():
                if self._reference_packet[i].__class__ != packet[i].__class__:
                    self._comparison_diagnosis = \
                        "Packet header type is wrong at index {}: expecting {} but found {}".format(
                            i, self._reference_packet[i].__class__.__name__, 
                            packet[i].__class__.__name__)
                    return False
                i += 1

            if i < packet.num_headers():
                extras = ' | '.join([packet[j].__class__.__name__ for j in range(i, packet.num_headers())])
                self._comparison_diagnosis = "Extra headers found in your packet: {}".format(extras)
                return False

            if i < self._reference_packet.num_headers():
                missing = ' | '.join([self._reference_packet[j].__class__.__name__ for j in range(i, self._reference_packet.num_headers())])
                self._comparison_diagnosis = "Missing headers in your packet: {}".format(missing)
                return False

            return True

        def _compare_header_attrs(packet):
            differences = []
            for i,hdr in enumerate(self._reference_packet):
                attrlist = self._comparison_attrs.get(hdr.__class__, [])
                diffs = []
                for attr in attrlist:
                    refattr = getattr(hdr, attr)
                    curattr = getattr(packet[i], attr)
                    if refattr != curattr:
                        diffs.append("{} is wrong (is {} but should be {})".format(attr, curattr, refattr))

                if diffs:
                    diffstr = '; '.join(diffs)
                    differences.append("In the {} header, {}".format(hdr.__class__.__name__, diffstr))
            if differences:
                self._comparison_diagnosis = ', '.join(differences)
            return len(differences) == 0
            
        return _compare_header_types(packet) and _compare_header_attrs(packet)

    def _showpkt(self, pkt):
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

        pktcopy = deepcopy(pkt)
        for klass,attr in self._wildcards:
            header = pktcopy.get_header(klass)
            if header is not None:
                star_out_attr(header, attr)
        return str(pktcopy)

    def fail_reason(self, packet):
        '''
        Construct/return a string that describes why a packet doesn't
        match this matcher.
        '''
        results = self._lastresults
        firstmatch = results.pop(0)
        xtype = "exact" if self._exact else "inexact"
        wc = "with wildcards " if self._wildcards else "" 
        aan = 'an' if xtype == 'exact' else 'a'
        xresults = "passed" if firstmatch else "failed"
        conjunction = ', but' if firstmatch else '. '
        diagnosis = ["{} {} match {}of packet contents {}{}".format(aan, xtype, wc, xresults, conjunction)]

        # are there predicates that were tested?  
        if len(results):
            diagnosis += ["when comparing the packet you sent versus what I expected,"]
            # if previous statement ended with sentence, cap the last
            # statement added.
            if diagnosis[-2].endswith('.'):
                diagnosis[-1] = diagnosis[-1].capitalize()

            # go through each predicate
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
            diagnosis += ["\nPacket field comparisons matched correctly: {}.".format(self._showpkt(packet))]
        else:
            diagnosis.append(self._comparison_diagnosis)

            if VerboseOutput.enabled():
                diagnosis[-1] += '.'
                # packet header match failed
                diagnosis += ["\nDetails: here is the packet that failed the check: {},".format(packet)]
                diagnosis += ["\nand here is what I expected to match: {}".format(self._showpkt(packet))]
        return ' '.join(diagnosis)

    def match(self, packet):
        '''
        Determine whether packet matches our expectation.
        The packet is only a match if it meets WildcardMatch
        criteria, and all predicates return True.
        If no match, then construct a "nice" description
            of what doesn't match, and throw an exception.
        '''
        # we don't need the binary representation, but we do need to ensure
        # that any pre_serialization triggers have been executed to fill in
        # various headers correctly.
        packet.to_bytes()
        self._reference_packet.to_bytes()

        self._lastresults = [ self._compare_packet_against_reference(packet) ]
        self._lastresults += [ eval(fn)(packet) for fn in self._predicates ]
        if all(self._lastresults):
            return True
        else:
            return False

    def __getstate__(self):
        rv = self.__dict__.copy()
        rv['_reference_packet'] = rv['_reference_packet'].to_bytes()
        return rv

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)
        self._reference_packet = Packet(raw=self._reference_packet, first_header=self._first_header)



class SwitchyardTestEvent(object):
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
        return SwitchyardTestEvent.MATCH_FAIL

    @abstractmethod
    def fail_reason(self):
        pass

    def format_pkt(self, pkt):
        '''
        Return a string representation of a packet.  If display_class is a known
        header type, just show the string repr of that header.  Otherwise, dump
        the whole thing.
        '''
        cls = self._display
        if VerboseOutput.enabled():
            cls = None

        # no special header highlighted with display kw; just return the entire thing
        if cls is None:
            return str(pkt)

        idx = pkt.get_header_index(cls)
        if idx == -1:
            log_warn("Tried to find non-existent header for output formatting {}"
                " (test scenario probably needs fixing)".format(str(cls)))
            return str(pkt)
        hdrs = []
        for i in range(pkt.num_headers()):
            if i == idx:
                hdrs.append(str(pkt[i]))
            else:
                hdrs.append("{}...".format(pkt[i].__class__.__name__))
        return ' | '.join(hdrs)


class PacketInputTimeoutEvent(SwitchyardTestEvent):
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
        return "Timeout after {}s on a call to recv_packet".format(self._timeout)

    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketInputEvent currently ignores
        any additional arguments.
        '''
        if evtype == SwitchyardTestEvent.EVENT_INPUT:
            return SwitchyardTestEvent.MATCH_SUCCESS
        else:
            return SwitchyardTestEvent.MATCH_FAIL

    def generate_packet(self, timestamp, scenario):
        time.sleep(self._timeout)
        raise NoPackets()

    def fail_reason(self):
        return "Your code did not time out on a call to recv_packet"


class PacketInputEvent(SwitchyardTestEvent):
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
        if isinstance(copyfromlastout, (tuple,list)):
            if len(copyfromlastout) == 5 and isinstance(copyfromlastout[0], str):
                self._copyfromlastout = [ copyfromlastout ]
            elif isinstance(copyfromlastout[0], (tuple,list)):
                self._copyfromlastout = copyfromlastout
        elif copyfromlastout is not None:
            raise ValueError("An argument to copyfromlastout must be a list or tuple, or None")

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
        if evtype == SwitchyardTestEvent.EVENT_INPUT:
            return SwitchyardTestEvent.MATCH_SUCCESS
        else:
            return SwitchyardTestEvent.MATCH_FAIL

    def generate_packet(self, timestamp, scenario):
        # ensure that the packet is fully parsed before
        # delivering it.  cost is immaterial since this
        # is just testing code!
        self._packet = Packet(raw=self._packet.to_bytes(), first_header=self._first_header)
        if self._device not in scenario.interfaces():
            raise TestScenarioFailure("Test scenario problem: input event refers to an interface ({}) that is not configured in the scenario (these are the interfaces configured: {})".format(self._device, ', '.join(scenario.interfaces().keys())))
        if self._copyfromlastout:
            for i in range(len(self._copyfromlastout)):
                intf,outcls,outprop,incls,inprop = self._copyfromlastout[i]
                hdrval = scenario.lastout(intf, outcls, outprop)
                hdr = self._packet.get_header(incls)
                setattr(hdr, inprop, hdrval)
        return ReceivedPacket(timestamp=timestamp, input_port=self._device, packet=self._packet)

    def fail_reason(self):
        return "Your code did not call recv_packet"


class PacketOutputEvent(SwitchyardTestEvent):
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
            pval = kwargs.pop('predicates')
            predicates.extend(pval)
        if 'predicate' in kwargs:
            pval = kwargs.pop('predicate')
            predicates.append(pval)

        wildcards = []
        if 'wildcards' in kwargs:
            wc = kwargs.pop('wildcards')
            wildcards.extend(wc)
        if 'wildcard' in kwargs:
            wc = kwargs.pop('wildcard')
            wildcards.append(wc)

        if len(args) == 0:
            raise ValueError("PacketOutputEvent expects a list of device1, pkt1, device2, pkt2, etc., but no arguments were given.")
        if len(args) % 2 != 0:
            raise ValueError("Arg list length to PacketOutputEvent must be even (device1, pkt1, device2, pkt2, etc.)")
        for i in range(0, len(args), 2):
            matcher = _PacketMatcher(args[i+1], predicates=predicates, wildcards=wildcards, **kwargs)
            self._device_packet_map[args[i]] = matcher

    def match(self, evtype, **kwargs):
        '''
        Does event type match me?  PacketOutputEvent requires
        two additional keyword args: device (str) and packet (packet object).
        '''
        if evtype != SwitchyardTestEvent.EVENT_OUTPUT:
            return SwitchyardTestEvent.MATCH_FAIL
        if 'device' not in kwargs or 'packet' not in kwargs:
            return SwitchyardTestEvent.MATCH_FAIL
        device = kwargs['device']
        pkt = kwargs['packet']

        if device in self._device_packet_map:
            matcher = self._device_packet_map[device]
            if matcher.match(pkt):
                self._matches[device] = pkt
                del self._device_packet_map[device]
                if len(self._device_packet_map) == 0:
                    return SwitchyardTestEvent.MATCH_SUCCESS
                else:
                    return SwitchyardTestEvent.MATCH_PARTIAL
            else:
                raise TestScenarioFailure("You called send_packet and while the output port {} is ok, {}.".format(device, matcher.fail_reason(pkt)))
        else:
            raise TestScenarioFailure("You called send_packet with an unexpected output port {}.  Here is what Switchyard expected: {}.".format(device, str(self)))

    def fail_reason(self):
        message = ""
        if len(self._matches):
            plural = "" if len(self._matches) == 1 else "s"
            message += "your code has sent a packet on port{} {}".format(plural,
                ",".join(self._matches.keys()))
            if len(self._device_packet_map):
                message += ", but "
        if len(self._device_packet_map):
            plural = "" if len(self._device_packet_map) == 1 else "s"
            if len(self._matches):
                message += "not "
            else:
                message += "your code did not send packet{0} ".format(plural)
            message += "on port{} {}".format(
                    plural, ','.join(self._device_packet_map.keys()))
        return message.capitalize()

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
            raise TestScenarioFailure('''An internal error appears to have happened. 
                next() was called on scenario '{}' to obtain the next expected event, 
                but Switchyard isn't expecting anything else for this scenario'''.format(self.name))
        else:
            return self._pending_events[0].event

    def failed_test_reason(self):
        return self._pending_events[0].event.fail_reason()

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
            raise TestScenarioFailure('''Switchyard expected your program to call send_packet in 
                order to match {} in scenario {}, but it wasn't called.  After {} seconds,
                Switchyard gave up.'''.format(str(self._pending_events[0]), self.name, self.timeout))
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
    def wrapevent(description, expected_event, show_details=True):
        '''
        Create a "pretty" version of an event description and expectation for output.
        '''
        baseindent = 4
        wraplen = 60
        expected_event = "Expected event: {}".format(expected_event)

        outstr = '\n'.join([' ' * baseindent + s for s in textwrap.wrap(description, wraplen)])
        if show_details:
            outstr += '\n'
            outstr += '\n'.join([' ' * (baseindent*2) + s for s in textwrap.wrap(expected_event, wraplen)])
        return outstr

    def print_summary(self):
        '''
        Print a semi-nice summary of the test scenario: what passed, what
        failed, and test components that haven't been checked yet due to
        a prior failure.
        '''
        with blue():
            print ("\nResults for test scenario {}:".format(self.name), end=' ')
            print ("{} passed, {} failed, {} pending".format(len(self._completed_events), min(1,len(self._pending_events)), max(0,len(self._pending_events)-1)))

        if len(self._completed_events):
            with green():
                print ("\nPassed:")
                for idx,ev in enumerate(self._completed_events):
                    idxstr = str(idx+1)
                    print ("{}{}".format(idxstr, self.wrapevent(ev.description, str(ev.event), VerboseOutput.enabled())[len(idxstr):]))

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
                        print ("{}{}".format(idxstr, self.wrapevent(ev.description, str(ev.event), VerboseOutput.enabled())[len(idxstr):]))
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

        Returns bool (True if no warnings, False if there are warnings)
        '''
        nowarnings = True
        log_debug("Doing sanity check on test scenario {}".format(self.name))
        for ev in self._pending_events:
            if isinstance(ev.event, PacketInputEvent):
                if ev.event._device not in self._interface_map:
                    log_warn("PacketInputEvent ({}) refers to a device not part of scenario interface map".format(str(ev.event)))
                    nowarnings = False
                if not isinstance(ev.event._packet, Packet):
                    log_warn("PacketInputEvent ({}) refers to a non-packet object ({})".format(str(ev.event), type(ev.event._packet)))
                    nowarnings = False
            elif isinstance(ev.event, PacketOutputEvent):
                if not len(ev.event._device_packet_map):
                    log_warn("PacketOutputEvent ({}) doesn't have any output devices included".format(ev.event))
                    nowarnings = False
                for dev,pkt in ev.event._device_packet_map.items():
                    if dev not in self._interface_map:
                        log_warn("PacketOutputEvent () refers to a device not part of test scenario".format(str(ev.event)))
                        nowarnings = False
                    if not isinstance(pkt, _PacketMatcher):
                        log_warn("PacketOutputEvent ({}) refers to a non-PacketMatcher object ({}).  This is probably an internal error.".format(str(ev.event), type(pkt)))
                        nowarnings = False
                    if pkt._predicates:
                        for pred in pkt._predicates:
                            try:
                                xfn = eval(pred)
                            except Exception as e:
                                log_warn("Couldn't eval the predicate ({}): {}".format(pred, str(e)))
                                nowarnings = False
            elif isinstance(ev.event, PacketInputTimeoutEvent):
                pass
            else:
                log_warn("Unrecognized event type in scenario event list: {}".format(str(type(ev.event))))
                nowarnings = False
        return nowarnings

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
        sobj.scenario_sanity_check()
    elif fnmatch.fnmatch(sfile, "*.srpy"):
        sobj = uncompile_scenario(sfile)
    else:
        sobj = import_or_die(sfile, ('scenario',))
    return sobj
