import topobuild
import networkx as nx
import matplotlib.pyplot as pyp

def convert_to_networkx(cn_topo):
    '''
    Convert the toolbelt topology to a networkx graph.
    '''
    G = nx.Graph()
    for n,ndict in cn_topo.nodes.iteritems():
        G.add_node(n, **ndict)
    for etup,edict in cn_topo.links.iteritems():
        G.add_edge(etup[0], etup[1], **edict)
    return G

def show_graph(cn_topo):
    '''
    Display the toolbelt topology (after a conversion to a networkx graph)
    '''
    G = convert_to_networkx(cn_topo)
    nx.draw_networkx(G)
    pyp.show()

def save_graph(cn_topo, filename):
    '''
    Save the topology to an image file (after conversion to networkx graph)
    '''
    G = convert_to_networkx(cn_topo)
    nx.draw_networkx(G)
    pyp.savefig(filename)

def load_from_file(filename):
    '''
    Load a toolbelt topology from filename and return it.
    '''
    t = None
    with open(filename) as infile:
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

