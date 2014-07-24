#!/usr/bin/env python3

import sys
import os
sys.path.append(os.getcwd())
import argparse

from switchyard.lib.topo import *
import switchyard.sys as syss

parser = argparse.ArgumentParser('switchyard cli')
parser.add_argument('--topology', '-t', type=str, help='Name of topology file to load')
#parser.add_argument('--switchcode', type=str, help='switchyard module to be executed at each switch in the network')
#parser.add_argument('--routercode', type=str, help='switchyard module to be executed at each router in the network')
#parser.add_argument('--hostcode', type=str, help='switchyard module to be executed at each host in the network')
parser.add_argument('--execmod', '-m', type=str, help='switchyard module to be executed at all nodes in the network')
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

syss.run_simulation(t, node=args.execmod)
