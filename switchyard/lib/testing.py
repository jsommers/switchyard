import switchyard.versioncheck

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
from dis import Bytecode


from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
import switchyard.lib.debug as sdebug
from switchyard.lib.importcode import import_or_die


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


class WildcardMatch(AbstractMatch):
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
    # FIXME: modify field names to more closely align with
    # openflow 1.4 spec, e.g., p147 in v1.4.0 spec: oxm_ofb_match_fields
    _LOOKUP = {
        'dl_src': [(Ethernet, 'src', ETHWILD)],
        'dl_dst': [(Ethernet, 'dst', ETHWILD)],
        'dl_type': [(Ethernet, 'ethertype', SINGLE)],
        'nw_src': [(IPv4, 'srcip', IP4WILD), (IPv6, 'srcip', IP6WILD)],
        'nw_dst': [(IPv4, 'dstip', IP4WILD), (IPv6, 'dstip', IP6WILD)],
        'nw_proto': [(IPv4, 'protocol', SINGLE), (IPv6, 'protocol', SINGLE)],
        'tp_src': [(TCP, 'srcport', SINGLE), (UDP, 'srcport', SINGLE), (ICMP, 'icmptype', SINGLE)],
        'tp_dst': [(TCP, 'dstport', SINGLE), (UDP, 'dstport', SINGLE), (ICMP, 'icmpcode', SINGLE)],
        'arp_tpa': [(Arp, 'targetprotoaddr', IP4WILD)],
        'arp_spa': [(Arp, 'senderprotoaddr', IP4WILD)],
        'arp_tha': [(Arp, 'targethwaddr', ETHWILD)],
        'arp_sha': [(Arp, 'senderhwaddr', ETHWILD)],
    }
    _BYHEADER = None

    def __init__(self, pkt, wildcard_fields):
        if WildcardMatch._BYHEADER is None:
            WildcardMatch._BYHEADER = defaultdict(list)
            for xkey, xlist in WildcardMatch._LOOKUP.items():
                for cls, headerfield, wildfmt in xlist:
                    WildcardMatch._BYHEADER[cls].append(xkey)
        self.__wildcards = list(wildcard_fields)
        self.__matchvals = self.__buildmvals(pkt)

    def __buildmvals(self, pkt):
        mvals = {}
        for key,llist in WildcardMatch._LOOKUP.items():

            # only build a comparison table of fields that aren't
            # listed in wildcards
            if key in self.__wildcards:
                continue

            for cls,field,_ in llist:
                if pkt.has_header(cls):
                    header = pkt.get_header(cls)
                    value = getattr(header,field)
                    mvals[key] = value
        return mvals

    def match(self, pkt):
        mvals = self.__buildmvals(pkt)
        return mvals == self.__matchvals

    def __str__(self):
        return 'Wildcarded fields: {}'.format(' '.join(self.__wildcards))

    def __getstate__(self):
        d = self.__dict__.copy()
        return d

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)

    def __getattr__(self, attr):
        if attr in self.__matchvals:
            return self.__matchvals[attr]
        raise AttributeError("No such attribute {}".format(attr))

    def show(self, comparepkt):
        def fill_field(field, header):
            for clsname,attr,wilddisplay in WildcardMatch._LOOKUP[field]:
                if isinstance(header, clsname):
                    # print (field, attr, self.__wildcards)
                    if field in self.__wildcards:
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
        for clsname, fmt in WildcardMatch._SHOWORDER:
            if comparepkt.has_header(clsname):
                headers.append(with_wildcards(comparepkt.get_header(clsname), fmt))
        return ' | '.join(headers)


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
        self.exact = bool(kwargs.get('exact', True))
        wildcard = kwargs.get('wildcard', [])

        if self.exact and wildcard:
            log_warn("Wildcards given but exact match specified.  Ignoring wildcards.")
        kws = set(kwargs.keys())
        kws.discard('exact')
        kws.discard('wildcard')
        if len(kws):
            log_warn("Unrecognized keyword arguments given to PacketMatcher: {}".format(' '.join(kws)))

        if self.exact:
            self.__matchobj = ExactMatch(packet)
        else:
            self.__matchobj = WildcardMatch(packet, wildcard)

        self._packet = packet

        self.predicates = []
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
                self.predicates.append(predicates[i])

    @property
    def packet(self):
        return self._packet

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

        # are there predicates that were tested?
        if len(results):
            diagnosis += ["when comparing the packet you sent versus what I expected,"]
            # if previous statement ended with sentence, cap the last
            # statement added.
            if diagnosis[-2].endswith('.'):
                diagnosis[-1] = diagnosis[-1].capitalize()

            for pidx,preresult in enumerate(results):
                xresults = "passed" if preresult else "failed"
                xname = self.predicates[pidx]
                conjunction = 'and' if pidx == len(results)-1 else ''
                diagnosis += ["{} the predicate ({}) {}".format(conjunction, xname, xresults)]
                if not conjunction:
                    diagnosis[-1] += ','
            diagnosis[-1] += '.'

        if firstmatch: 
            # headers match, but predicate(s) failed
            diagnosis += ["\nThis part matched: {}.".format(self.__matchobj.show(packet))]
        else:
            # packet header match failed
            diagnosis += ["\nHere is the packet that failed the check: {}.".format(packet)]

            if self.exact:
                diagnosis += ["\nHere is exactly what I expected: {}.".format(self.__matchobj.show(packet))]
            else:
                diagnosis += ["\nHere is what I expected to match: {}.".format(self.__matchobj.show(packet))]
        return ' '.join(diagnosis)

    def match(self, packet):
        '''
        Determine whether packet matches our expectation.
        The packet is only a match if it meets WildcardMatch
        criteria, and all predicates return True.
        If no match, then construct a "nice" description
            of what doesn't match, and throw an exception.
        '''
        results = [ self.__matchobj.match(packet) ]
        results += [ eval(fn)(packet) for fn in self.predicates ]
        if all(results):
            return True
        else:
            raise ScenarioFailure(self.__diagnose(packet, results))

    def __getstate__(self):
        rv = self.__dict__.copy()
        rv['_packet'] = rv['_packet'].to_bytes()
        return rv

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)
        self._packet = Packet(raw=self._packet)

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
        return self.timeout == other.timeout

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
        rv = self.__dict__.copy()
        rv['packet'] = self.packet.to_bytes()
        return rv

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)
        self.packet = Packet(raw=self.packet)

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
        self.packet = Packet(raw=self.packet.to_bytes())
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
        two additional keyword args: device (str) and packet (packet object).
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
        # in device_packet_map, values are Match objects
        devlist = ["{} out {}".format(self.format_pkt(v.packet),k) for k,v in self.device_packet_map.items() ]
        # in matches, values are packets
        devlist += ["{} out {}".format(self.format_pkt(v),k) for k,v in self.matches.items() ]
        s += ' and '.join(devlist)
        return s

    def __getstate__(self):
        rv = self.__dict__.copy()
        for dev in rv['matches']:
            pkt = rv['matches'][dev].to_bytes()
            rv['matches'][dev] = pkt
        return rv

    def __setstate__(self, xdict):
        self.__dict__.update(xdict)
        for dev in self.matches:
            raw = self.matches[dev]
            pkt = Packet(raw=raw)
            self.matches[dev] = pkt

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
        self._name = name
        self.pending_events = []
        self.completed_events = []
        self.timer = False
        self.next_timestamp = 0.0
        self._timeoutval = 60
        self.support_files = {}
        self._setup = None
        self._teardown = None

    @property  
    def name(self):
        return self._name

    @property
    def timeout(self):
        return self._timeoutval

    @timeout.setter
    def timeout(self, value):
        self._timeoutval = int(value)

    def add_file(self, fname, text):
        self.support_files[fname] = text

    def write_files(self):
        for fname, text in self.support_files.items():
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

    def add_interface(self, interface_name, macaddr, ipaddr=None, netmask=None, ifnum=None):
        '''
        Add an interface to the test scenario.

        (str, str/EthAddr, str/IPAddr, str/IPAddr) -> None
        '''
        if ifnum is None:
            ifnum = len(self.interface_map)
        intf = Interface(interface_name, macaddr, ipaddr, netmask, ifnum)
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
            raise ScenarioFailure("next() called on scenario '{}', but not expecting anything else for this scenario".format(self.name))
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
        if sdebug.in_debugger:
            self.timer = False
            return

        if self.timer:
            log_debug("Timer expiration while expecting PacketOutputEvent")
            raise ScenarioFailure("Expected send_packet to be called to match {} in scenario {}, but it wasn't called, and after {} seconds I gave up.".format(str(self.pending_events[0]), self.name, self.timeout))
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
            signal.alarm(self.timeout)
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
        with blue():
            print ("\nResults for test scenario {}:".format(self.name), end='')
            print ("{} passed, {} failed, {} pending".format(len(self.completed_events), min(1,len(self.pending_events)), max(0,len(self.pending_events)-1)))

        if len(self.completed_events):
            with green():
                print ("\nPassed:")
                for idx,ev in enumerate(self.completed_events):
                    idxstr = str(idx+1)
                    print ("{}{}".format(idxstr, self.wrapevent(ev.description, str(ev.event))[len(idxstr):]))

        if len(self.pending_events):
            with red():
                print ("\nFailed:")
                failed_event = self.pending_events[0]
                print ("{}".format(self.wrapevent(failed_event.description, str(failed_event.event))))
            if len(self.pending_events) > 1:
                with yellow():
                    print ("\nPending (couldn't test because of prior failure):")
                    for idx,ev in enumerate(self.pending_events[1:]):
                        idxstr = str(idx+1)
                        print ("{}{}".format(idxstr, self.wrapevent(ev.description, str(ev.event))[len(idxstr):]))
        print()

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
        del odict['_setup']
        del odict['_teardown']
        # del odict['next_timestamp']
        return odict

    def __setstate__(self, xdict):
        xdict['pending_events'] = xdict['events']
        del xdict['events']
        # xdict['next_timestamp'] = 0.0
        xdict['timer'] = None
        xdict['completed_events'] = []
        xdict['_setup'] = None
        xdict['_teardown'] = None
        self.__dict__.update(xdict)

    def __eq__(self, other):
        if self.next_timestamp != other.next_timestamp:
            return False
        selfev = self.pending_events + self.completed_events
        otherev = other.pending_events + other.completed_events
        if len(selfev) != len(otherev):
            print ("ev len doesn't match")
            return False
        for i in range(len(selfev)):
            if selfev[i] != otherev[i]:
                print ("specific ev don't match")
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
                if not isinstance(ev.event.packet, Packet):
                    log_warn("PacketInputEvent ({}) refers to a non-packet object ({})".format(str(ev.event), type(ev.event.packet)))
            elif isinstance(ev.event, PacketOutputEvent):
                if not len(ev.event.device_packet_map):
                    log_warn("PacketOutputEvent ({}) doesn't have any output devices included".format(ev.event))
                for dev,pkt in ev.event.device_packet_map.items():
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
        raise SwitchyException("Couldn't load scenario file (hash digest doesn't match)")
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
