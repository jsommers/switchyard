import sys
from lib.topo.util import load_from_file

__author__ = 'jsommers@colgate.edu'
__doc__ = 'SwitchYard Substrate Simulator'


'''
create separate threads for each node simulated?
create a Queue to represent a link between each node?

once created, throw user into a CLI where they can interact with the network
    ping from one host to another
    show the network (in some way)
        simple view and detailed view (with all addresses/interfaces)
    go onto fake console for any node?
    reload code on any node?

    i.e., it will sort of work like mininet :-/
'''

def node_entry(swycode):
    pass

def run_simulation(topo, swycode):
    print topo
    for n in topo.nodes:
        print n,topo.nodes[n]

def main():
    topofile = None
    swycode = None
    if len(sys.argv) > 1:
        topofile = sys.argv[1]
    if len(sys.argv) > 2:
        swycode = sys.argv[2]
    if not (topofile and swycode):
        print "Need topofile and swy code"
        sys.exit(-1)

    topo = load_from_file(topofile)
    run_simulation(topo, swycode)


if __name__ == '__main__':
    main()
