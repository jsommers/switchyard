import sys
import argparse
import os
import signal
import re
import subprocess
import time
import threading
from queue import Queue,Empty
import importlib
import bz2
import hashlib
import pickle
import base64
import fnmatch
import copy
import textwrap
from collections import namedtuple

from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *


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
            results = [ copy.deepcopy(packet).to_bytes() == self.__matchobj.to_bytes() ]
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
        self.packet = Packet(raw=self.packet.pack())
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
        devlist = ["{} out {}".format(v.show(self.display),k) for k,v in self.device_packet_map.items() ]
        devlist += ["{} out {}".format(self.format_pkt(v),k) for k,v in self.matches.items() ]
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

