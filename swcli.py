#!/usr/bin/env python3

from switchyard.lib.topo import *
import switchyard.sys as syss
import sys

t = load_from_file('testtopo.txt')
syss.run_simulation(t, 'myhub')
