from switchyard.lib.topo import topobuild
import networkx as nx
import matplotlib.pyplot as pyp
import re

def convert_to_networkx(cn_topo):
    '''
    Convert the toolbelt topology to a networkx graph.
    '''
    G = nx.Graph()
    elabels = {}
    nlabels = {}
    for nodename,nodeobj in cn_topo.nodes.items():
        # print nodename,nodeobj.asDict()
        G.add_node(nodename)
        nlabels[nodename] = nodename
    for nodename,edict in cn_topo.links.items():
        for nextnode,edgeinfo in edict.items():
            elabels[(nodename,nextnode)] = "{} Mb/s {} sec".format(edgeinfo['capacity']/1000000.0, edgeinfo['delay'])
            # print edgeinfo
            G.add_edge(nodename, nextnode)
    return G,nlabels,elabels

def __do_draw(cn_topo):
    G,nlabels,elabels = convert_to_networkx(cn_topo)
    pos=nx.spring_layout(G)
    nx.draw_networkx(G, pos=pos, label=cn_topo.name, with_labels=True, labels=nlabels, edge_labels=elabels)
    nx.draw_networkx_edge_labels(G, pos=pos, edge_labels=elabels)

def show_graph(cn_topo):
    '''
    Display the toolbelt topology (after a conversion to a networkx graph)
    '''
    __do_draw(cn_topo)
    pyp.show()

def save_graph(cn_topo, filename):
    '''
    Save the topology to an image file (after conversion to networkx graph)
    '''
    __do_draw(cn_topo)
    pyp.savefig(filename)

def load_from_file(filename):
    '''
    Load a toolbelt topology from filename and return it.
    '''
    t = None
    with open(filename, 'rU') as infile:
        tdata = infile.read()
        t = topobuild.Topology.unserialize(tdata)
    return t

def save_to_file(cn_topo, filename):
    '''
    Save a toolbelt topology to a file.
    '''
    jstr = cn_topo.serialize()
    with open(filename, 'w') as outfile:
        outfile.write(jstr)

def humanize_bandwidth(bits):
    '''
    Accept some number of bits/sec (i.e., a link capacity) as an
    integer, and return a string representing a 'human'(-like)
    representation of the capacity, e.g., 10 Mb/s, 1.5 Mb/s,
    900 Gb/s.

    As is the standard in networking, capacity values are assumed
    to be base-10 values (not base 2), so 1000 is 1 Kb/s.
    '''
    unit = ''
    divisor = 1
    if bits < 1000:
        unit = 'bits'
        divisor = 1
    elif bits < 1000000:
        unit = 'Kb'
        divisor = 1000
    elif bits < 1000000000:
        unit = 'Mb'
        divisor = 1000000
    elif bits < 1000000000000:
        unit = 'Gb'
        divisor = 1000000000
    elif bits < 1000000000000000:
        unit = 'Tb'
        divisor = 1000000000000
    else:
        raise Exception("Can't humanize that many bits.")

    if bits % divisor == 0:
        value = int(bits/divisor)
    else:
        value = bits/divisor

    return "{} {}/s".format(value, unit)

def unhumanize_bandwidth(bitsstr):
    '''
    Take a string representing a link capacity, e.g., 10 Mb/s, and
    return an integer representing the number of bits/sec.
    Recognizes:
        - 'bits/sec' or 'b/s' are treated as plain bits per second
        - 'Kb' or 'kb' as thousand bits/sec
        - 'Mb' or 'mb' as million bits/sec
        - 'Gb' or 'gb' as billion bits/sec
        - 'Tb' or 'tb' as trillion bits/sec
        - if second character is 'B', quantity is interpreted as bytes/sec
        - any subsequent characters after the first two are ignored, so
          Kb/s Kb/sec Kbps are interpreted identically.
    '''
    pass

def humanize_delay(delay):
    '''
    Accept a floating point number presenting link propagation delay
    in seconds (e.g., 0.1 for 100 milliseconds delay), and return
    a human(-like) string like '100 milliseconds'.
    '''
    pass

def unhumanize_delay(delaystr):
    '''
    Accept a string representing link propagation delay (e.g., 
    '100 milliseconds' or '100 msec' or 100 millisec') and return
    a floating point number representing the delay in seconds.
    Recognizes:
        - us, usec, micros* all as microseconds
        - ms, msec, millisec* all as milliseconds
        - s, sec* as seconds
    '''
