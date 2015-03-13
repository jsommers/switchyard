#!/usr/bin/env python3

import sys
import os
sys.path.append(os.getcwd())

import switchyard.versioncheck

import argparse
from switchyard.lib.common import *
from switchyard.lib.topo import *
from switchyard.cli import run_simulation

parser = argparse.ArgumentParser('switchyard cli')
parser.add_argument('--topology', '-t', type=str, help='Name of topology file to load')
parser.add_argument('--execmod', '-m', type=str, help='switchyard module to be executed at all nodes in the network')
parser.add_argument('--debug','-d', action='store_true', help='turn on debugging log output')
args = parser.parse_args()

if args.topology:
    try:
        t = load_from_file(args.topology)
    except FileNotFoundError:
        print ("No such file {} exists to load topology.".format(args.topology))
        sys.exit()
else:
    # if no topology file specified, create a blank topology
    t = Topology()

setup_logging(args.debug)

run_simulation(t, nodeexec=args.execmod)
