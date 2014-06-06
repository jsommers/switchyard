import topobuild
import networkx as nx
import matplotlib.pyplot as pyp

def convert_to_networkx(cn_topo):
    '''
    Convert the toolbelt topology to a networkx graph.
    '''
    G = nx.Graph()
    elabels = {}
    nlabels = {}
    for nodename,nodeobj in cn_topo.nodes.iteritems():
        # print nodename,nodeobj.asDict()
        G.add_node(nodename)
        nlabels[nodename] = nodename
    for nodename,edict in cn_topo.links.iteritems():
        for nextnode,edgeinfo in edict.iteritems():
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
