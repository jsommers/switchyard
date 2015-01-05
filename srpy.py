#!/usr/bin/env python3

import sys
import os
sys.path.append(os.getcwd())
import argparse
from threading import Thread, Barrier

from switchyard.lib.common import *
from switchyard.lib.textcolor import *
from switchyard.lib.hostfirewall import Firewall
from switchyard.switchy_test import main_test
from switchyard.switchy_real import main_real, PyLLNet
from switchyard.lib.importcode import import_or_die
from switchyard.lib.socketemu import ApplicationLayer

setup_ok = False
netobj = None

def start_app(appcode, firewall_setup):
    # don't start app-layer code until the lower layers are initialized
    firewall_setup.wait()
    # and beware that something may have failed, so only start app code
    # if it looks like everything was initialized correctly
    if setup_ok:
        import_or_die(appcode, [])
    print("After app-code")
    if netobj is not None:
        netobj.shutdown()

if __name__ == '__main__':
    progname = "srpy"
    parser = argparse.ArgumentParser(prog=progname)
    parser.add_argument("-t", "--test", help="Run {} in testing mode.".format(progname), dest="testmode", action="store_true", default=False)
    parser.add_argument("-i", "--include", metavar='INCLUDE_INTF', help="Specify interface names to include/use for data plane traffic (default: all non-loopback interfaces).", dest="intf", action='append')
    parser.add_argument("-x", "--exclude", metavar='EXCLUDE_INTF', help="Specify interface names to exclude in {}.  All other non-loopback interfaces will be used.".format(progname), dest="exclude", action='append')
    parser.add_argument('usercode', metavar="YOURCODE", type=str, nargs='?', help='User switch/router code to execute.')
    parser.add_argument("-c", "--compile", help="Compile scenario to binary format for distribution.", dest="compile", action="store_true", default=False)
    parser.add_argument("-s", "--scenario", help="Specify scenario file to use in test mode.", dest="scenario", action="append")
    parser.add_argument("--dryrun", help="Get everything ready to go, but don't actually do anything.", action='store_true', dest='dryrun', default=False)
    parser.add_argument("-v", "--verbose", help="Turn on verbose output, including full packet dumps in test results.  Can be specified multiple times to increase verbosity.", dest="verbose", action="count", default=0)
    parser.add_argument("-d", "--debug", help="Turn on debug logging output.", dest="debug", action="store_true", default=False)
    parser.add_argument("--nopdb", help="Don't enter pdb on crash.", dest="nopdb", action="store_true", default=False)
    parser.add_argument("-f", "--firewall", help="Specify host firewall rules (for real/live mode only)", dest="fwconfig", action="append")
    parser.add_argument("-a", "--app", help="Specify application layer (socket-based) program to start (EXPERIMENTAL!)", dest="app", default=None)
    args = parser.parse_args()

    # assume test mode if the compile flag is set
    if args.compile:
        args.testmode = True

    if args.verbose:
        PacketFormatter.full_display(True)

    setup_logging(args.debug)

    if args.usercode is None and not args.compile:
        log_failure("You need to specify the name of your module to run as the last argument")
        sys.exit()

    waiters = 1
    if args.app:
        waiters = 2
    barrier = Barrier(waiters)

    if args.app:
        ApplicationLayer.init()
        _appt = Thread(target=start_app, args=(args.app,barrier))
        _appt.start()

    if args.testmode:
        if args.usercode and args.compile:
            log_info("You specified user code to run with compile flag, but I'm just doing compile.")
        main_test(args.compile, args.scenario, args.usercode, args.dryrun, args.nopdb, args.verbose)
    else:
        if os.geteuid() != 0:
            log_warn("You're running in real mode, but not as root.  "
                "You should expect errors, but I'm going to "
                "continue anyway.")
        if args.exclude is None:
            args.exclude = []
        if args.intf is None:
            args.intf = []

        if args.app:
            args.fwconfig = []
        elif args.fwconfig is None:
            args.fwconfig = ('all',)

        devlist = make_device_list(args.intf, args.exclude)
        if not devlist:
            log_failure("There are no network interfaces I can use after processing include/exclude lists")
            alldevs = make_device_list([], [])
            log_failure("Here are all the interfaces I see on your system: {}".format(', '.join(list(alldevs))))
            barrier.wait()
            sys.exit()

        with Firewall(devlist, args.fwconfig):
            setup_ok = True
            barrier.wait()
            netobj = PyLLNet(devlist)
            main_real(args.usercode, args.dryrun, netobj, args.nopdb, args.verbose)
