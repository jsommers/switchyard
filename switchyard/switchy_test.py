import sys
import argparse
import os
import signal
import re
import subprocess
import time
from queue import Queue, Empty
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
from switchyard.lib.testing import *
from switchyard.lib.importcode import import_or_die
from switchyard.lib.debug import *


class FakePyLLNet(LLNetBase):

    '''
    A class that can used for testing code that uses PyLLNet.  Doesn't
    actually do any "real" network interaction; just manufactures
    packets of various sorts to test whether an IP router using this
    class behaves in what appear to be correct ways.
    '''

    def __init__(self, scenario, name=None):
        LLNetBase.__init__(self)
        self.devinfo = scenario.interfaces()
        self.scenario = scenario
        self.timestamp = 0.0
        if name:
            self.__name = name
        else:
            self.__name = scenario.name

    @property
    def name(self):
        return self.__name

    def shutdown(self):
        '''
        For FakePyLLNet, do nothing.
        '''
        pass

    def recv_packet(self, timeout=None, timestamp=False):
        '''
        Receive packets from any device on which one is available.
        Blocks until it receives a packet unless a timeout value >= 0 is
        supplied.  Raises Shutdown exception when device(s) are shut 
        down (i.e., on a SIGINT to the process) and raises NoPackets
        if there are no packets that could be read before a timeout occurred.

        Returns a tuple of length 2 or 3, depending whether the timestamp
        is desired.

        * device: network device name on which packet was received as a string
        * timestamp: floating point value of time at which packet was received
        * packet: Switchyard Packet object
        '''
        # check if we're done with test scenario
        if self.scenario.done():
            raise Shutdown()

        ev = self.scenario.next()
        if ev.match(SwitchyTestEvent.EVENT_INPUT) == SwitchyTestEvent.MATCH_SUCCESS:
            self.scenario.testpass()
            return ev.generate_packet(timestamp, self.timestamp)
        else:
            self.scenario.testfail(
                "recv_packet called, but I was expecting {}".format(str(ev)))

    def send_packet(self, devname, pkt):
        if self.scenario.done():
            raise ScenarioFailure(
                "send_packet was called, but the test scenario was finished.")

        if isinstance(devname, int):
            devname = self._lookup_devname(devname)

        if isinstance(devname, Interface):
            devname = devname.name

        ev = self.scenario.next()
        match_results = ev.match(
            SwitchyTestEvent.EVENT_OUTPUT, device=devname, packet=pkt)
        if match_results == SwitchyTestEvent.MATCH_SUCCESS:
            self.scenario.testpass()
        elif match_results == SwitchyTestEvent.MATCH_FAIL:
            self.scenario.testfail(
                "send_packet was called, but I was expecting {}".format(str(ev)))
        else:
            # Not a pass or fail yet: means that we
            # are expecting more PacketOutputEvent objects before declaring
            # that the expectation matches/passes
            pass
        self.timestamp += 1.0

def _prepare_debugger(tb):
    '''
    Figure out which stack frame in traceback (tb) is the "right" one in which
    to put the user and adjust the debugger session to make sure it starts
    there.  We start in the first frame up from the bottom that is *not*
    part of switchyard code (i.e., first frame in which we see user code).
    '''
    p = pdb.Pdb(
        skip=['switchyard.lib.testing', 'switchyard.switchy_test'])
    p.reset()

    usercode = height = 0
    xtb = tb
    while xtb is not None:
        codestr = str(xtb.tb_frame.f_code)
        xtb = xtb.tb_next
        height += 1
        syscode = (
            'switchyard/switchy_test.py' in codestr or 'switchyard/lib/testing.py' in codestr)
        if not syscode:
            usercode = height

    # automatically starts at the bottom of the stack (newest)
    # go up as many frames as it takes to get to user code (crash
    # may have occurred while calling into a library function)
    p.setup(None, tb)

    for i in range(height-usercode):
        p.onecmd('up')

    return p


def run_tests(scenario_names, usercode_entry_point, options):
    '''
    Given a list of scenario names, set up fake network object with the
    scenario objects, and invoke the user module.

    (list(str), function, options/args) -> None
    '''
    for sname in scenario_names:
        sobj = get_test_scenario_from_file(sname)
        sobj.write_files()
        sobj.do_setup()
        net = FakePyLLNet(sobj)

        log_info("Starting test scenario {}".format(sname))
        exc, value, tb = None, None, None
        message = '''All tests passed!'''
        try:
            usercode_entry_point(net)
        except Shutdown:
            pass
        except ScenarioFailure:
            exc, value, tb = sys.exc_info()
            if sobj.get_failed_test():
                message = '''Your code didn't crash, but a test failed.'''
            else:
                message = '''Your code didn't crash, but something unexpected happened.'''
        except Exception:
            exc, value, tb = sys.exc_info()
            message = '''Your code crashed (or caused a crash) before I could run all the tests.'''
        else:
            # it's possible that no exception gets raised, but that not all scenario steps are
            # completed.  if a failed test exists, then adjust the final output
            # message.
            if sobj.get_failed_test():
                message = '''Your code didn't crash, but a test failed.'''

        sobj.do_teardown()

        # there may be a pending SIGALRM for ensuring test completion;
        # turn it off.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)

        sobj.print_summary()

        # if we got an exception, print some contextual information
        # and dump the user into pdb to try to see what happened.
        if value is not None:
            failurecontext = ''
            if sobj.get_failed_test() is not None:
                failurecontext = '\n'.join(
                    [' ' * 4 + s for s in textwrap.wrap(sobj.get_failed_test().description, 60)])
                failurecontext += '\n{}In particular:\n'.format(' ' * 4)
            failurecontext += '\n'.join([' ' * 8 +
                                         s for s in textwrap.wrap(repr(value), 60)])

            with red():
                print ('''{}
{}
{}

This is the Switchyard equivalent of the blue screen of death.
Here (repeating what's above) is the failure that occurred:

{}
'''.format('*' * 60, message, '*' * 60, failurecontext), file=sys.stderr)

            if not options.verbose:
                message = '''You can rerun with the -v flag to include full dumps of
packets that may have caused errors. (By default, only relevant packet
context may be shown, not the full contents.)'''
                print(textwrap.fill(message, 70))
                print()

            if options.nohandle:
                raise Exception(exc).with_traceback(tb)

            if options.nopdb:
                print(textwrap.fill(
                    "You asked not to be put into the Python debugger.  You got it.", 70))
            else:
                print ('''
I'm throwing you into the Python debugger (pdb) at the point of failure.
If you don't want pdb, use the --nopdb flag to avoid this fate.

    - Type "help" or "?" to get a list of valid debugger commands.
    - Type "exit" to get out.
    - Type "where" or "bt" to print a full stack trace.
    - You can use any valid Python commands to inspect variables
      for figuring out what happened.

''')

                if tb is not None:
                    dbg = _prepare_debugger(tb)
                    dbg.cmdloop()


                else:
                    print("No exception traceback available")

        else:
            with green():
                print('{}'.format(message), file=sys.stderr)


def main_test(usercode, scenarios, options):
    '''
    Entrypoint function for either compiling or running test scenarios.
    '''
    if not scenarios or not len(scenarios):
        log_failure("In test mode, but no scenarios specified.")
        return

    if options.compile:
        for scenario in scenarios:
            log_info("Compiling scenario {}".format(scenario))
            compile_scenario(scenario)
    else:
        usercode_entry_point = import_or_die(
            usercode, ('main', 'srpy_main', 'switchy_main'))
        if options.dryrun:
            log_info("Imported your code successfully.  Exiting dry run.")
            return
        run_tests(scenarios, usercode_entry_point, options)
