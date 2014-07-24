#!/usr/bin/env python3

import sys
import argparse
import os

from switchyard.switchyard.switchy_common import Interface, SwitchyException, Shutdown, NoPackets, ScenarioFailure, PacketFormatter
from switchyard.switchyard.switchy_common import setup_logging, log_info, log_debug, log_warn, log_failure
from switchyard.lib.textcolor import *
import switchyard.lib.pcapffi
from switchyard.switchyard.switchy import main_real, main_test

if __name__ == '__main__':
    progname = "srpy"
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

    if args.testmode:
        if args.usercode and args.compile:
            log_info("You specified user code to run with compile flag, but I'm just doing compile.")
        main_test(args.compile, args.scenario, args.usercode, args.dryrun, args.nopdb, args.verbose)
    else:
        if args.environ not in ['linux', 'mininet']:
            log_failure("Runtime environment {} is not valid.  'linux' and 'mininet' are the only valid environments, currently".format(args.environ))
            sys.exit(-1)

        if os.getuid() != 0:
            with blue():
                print ('''
You're running in real mode, but not as root.  You should
expect errors, but I'm going to continue anyway.''')

        if args.exclude is None:
            args.exclude = []
        if args.intf is None:
            args.intf = []
        main_real(args.usercode, args.dryrun, args.environ, args.intf, args.exclude)
