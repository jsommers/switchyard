#!/usr/bin/env python3

import sys
import os
sys.path.append(os.getcwd())
import argparse

from switchyard.syinit import start_framework

def version_check():
    required = (3,4)
    this = (sys.version_info.major, sys.version_info.minor)
    if this < required:
        log_failure("Invalid Python version for using Switchyard: need at least 3.4")
        sys.exit(-1)

def main():
    version_check()

    progname = "swyard"
    parser = argparse.ArgumentParser(prog=progname)
    parser.add_argument("-i", "--include", metavar='INCLUDE_INTF', 
        help="Specify interface names to include/use for data plane traffic "
             "(default: all non-loopback interfaces).", 
        dest="intf", action='append')
    parser.add_argument("-x", "--exclude", metavar='EXCLUDE_INTF', 
        help="Specify interface names to exclude in {}.  "
             "All other non-loopback interfaces will be used.".format(progname), 
             dest="exclude", action='append')
    parser.add_argument('usercode', metavar="YOURCODE", type=str, nargs='?', 
        help='User switch/router code to execute.')
    parser.add_argument("-g", "--codearg", metavar="YOURCODE_ARGS", 
        type=str, default='', 
        help='Arguments to pass to your code (if multiple args, they need to be '
             ' quoted in the shell).')
    parser.add_argument("-c", "--compile", 
        help="Compile test scenario to binary format for distribution.", 
        dest="compile", action="append", metavar="TEST_SCENARIO")
    parser.add_argument("-t", "--test", 
        help="Run {} in testing mode, using the given test "
             "scenario file.".format(progname), metavar="TESTSCENARIO", 
        dest="tests", action="append")
    parser.add_argument("--dryrun", 
        help="Get everything ready to go, but don't actually do anything.", 
        action='store_true', dest='dryrun', default=False)
    parser.add_argument("-v", "--verbose", 
        help="Turn on verbose output, including full packet dumps in test "
             "results. Can be specified multiple times to increase verbosity.",
             dest="verbose", action="count", default=0)
    parser.add_argument("-d", "--debug", help="Turn on debug logging output.", 
        dest="debug", action="store_true", default=False)
    parser.add_argument("-l", "--logfile", help="Specify the name of a file to send"
        " log entries to (default is to send log to stdout/stderr).", 
        dest="logfile", default=None, type=str)
    parser.add_argument("--nopdb", help="Don't enter pdb on crash.", 
        dest="nopdb", action="store_true", default=False)
    parser.add_argument("-f", "--firewall", 
        help="Specify host firewall rules (for real/live mode only).", 
        dest="fwconfig", action="append")
    parser.add_argument("-a", "--app", 
        help="Specify application layer (socket-based) program to start.", 
        dest="app", default=None, metavar="SOCKET_APP")
    parser.add_argument("-e", "--nohandle", 
        help="Don't trap exceptions.  Use of this option is helpful if you want"
             " to use Switchyard with a different symbolic debugger than pdb.", 
             dest="nohandle", action="store_true", default=False)
    parser.add_argument("--cli", help="Enter switchyard simulation command-line (EXPERIMENTAL!)", 
        dest="cli", action="store_true", default=False)
    parser.add_argument("--topology", help="Specify topology to use for simulation"
        " (only used if --cli is specified).",
        dest="topology", type=str, default=None)
    args = parser.parse_args()
    if args.usercode is None and not args.compile:
        parser.print_usage()
        return -1
    start_framework(args)

if __name__ == '__main__':
    main()
