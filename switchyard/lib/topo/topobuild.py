import json
from collections import defaultdict
from switchyard.lib.address import EthAddr,IPAddr
from switchyard.lib.topo.util import unhumanize_capacity, unhumanize_delay, humanize_capacity, humanize_delay
from networkx import Graph
from networkx.readwrite import json_graph

class Interface(object):
    '''
    Class that models a single logical interface on a network
    device.  An interface has a name, 48-bit Ethernet MAC address,
    and (optionally) a 32-bit IPv4 address and mask.
    '''
    def __init__(self, name, ethaddr, ipaddr, netmask):
        self.__name = name
        self.ethaddr = ethaddr
        self.ipaddr = ipaddr
        self.netmask = netmask

    @property
    def name(self):
        return self.__name

    @property
    def ethaddr(self):
        return self.__ethaddr

    @ethaddr.setter
    def ethaddr(self, value):
        if isinstance(value, EthAddr):
            self.__ethaddr = value
        elif isinstance(value, str):
            self.__ethaddr = EthAddr(value)
        elif value is None:
            self.__ethaddr = '00:00:00:00:00:00'
        else:
            self.__ethaddr = value

    @property 
    def ipaddr(self):
        return self.__ipaddr

    @ipaddr.setter
    def ipaddr(self, value):
        if isinstance(value, IPAddr):
            self.__ipaddr = value
        elif isinstance(value, str):
            self.__ipaddr = IPAddr(value)
        elif value is None:
            self.__ipaddr = '0.0.0.0'
        else:
            self.__ipaddr = value

    @property 
    def netmask(self):
        return self.__netmask

    @netmask.setter
    def netmask(self, value):
        if isinstance(value, IPAddr):
            self.__netmask = value
        elif isinstance(value, str):
            self.__netmask = IPAddr(value)
        elif value is None:
            self.__netmask = '255.255.255.255'
        else:
            self.__netmask = value

    def __str__(self):
        s =  "{} mac:{}".format(str(self.name), str(self.ethaddr))
        if str(self.ipaddr) != '0.0.0.0':
            s += " ip:{}/{}".format(str(self.ipaddr), str(self.netmask))
        return s            

class Node(object):
    __slots__ = ['ifnum','__interfaces']
    def __init__(self, *args, **kwargs):
        self.ifnum = 0
        self.__interfaces = {}
        if 'interfaces' in kwargs:
            for ifname,ifstr in kwargs['interfaces'].items():
                ifcomponents = ifstr.split()
                mac = ifcomponents[1][4:]
                ipmask = ifcomponents[2].split(':')[1].split('/')
                self.__interfaces[ifname] = Interface(ifname, mac, ipmask[0], ipmask[1])

    @property
    def nodetype(self):
        return self.__class__.__name__

    @property
    def interfaces(self):
        return self.__interfaces

    def getInterface(self, devname):
        return self.__interfaces[devname]

    def addInterface(self, ethaddr=None, ipaddr=None, netmask=None):
        ifname = 'eth{}'.format(self.ifnum)
        self.ifnum += 1
        intf = Interface(ifname, ethaddr, ipaddr, netmask)
        self.__interfaces[ifname] = intf
        return ifname

    def __str__(self):
        s = '{} '.format(self.nodetype)
        s += ' '.join(sorted([str(intf) for intf in self.interfaces.values()]))
        return s 

    def asDict(self):
        ifdict = dict([(ifname,str(ifobj)) for ifname,ifobj in self.__interfaces.items()])
        return {'nodetype':self.__class__.__name__, 'interfaces':ifdict}

class Host(Node):
    def __init__(self, *args, **kwargs):
        Node.__init__(self, *args, **kwargs)

class Switch(Node):
    def __init__(self, *args, **kwargs):
        Node.__init__(self, *args, **kwargs)

class Router(Node):
    def __init__(self, *args, **kwargs):
        Node.__init__(self, *args, **kwargs)

class Encoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs):
        json.JSONEncoder.__init__(self, *args, **kwargs)

    def default(self, o):
        return o.asDict()

class Topology(object):
    __slots__ = ['__nxgraph','__hnum','__snum','__rnum']
    def __init__(self, name="No name topology", nxgraph=None):
        if nxgraph:
            self.__nxgraph = nxgraph
        else:
            self.__nxgraph = Graph(name=name)
        self.__hnum = 0
        self.__snum = 0
        self.__rnum = 0

    @property
    def name(self):
        return self.__nxgraph['name']

    @property
    def nxgraph(self):
        return self.__nxgraph

    def __addNode(self, name, cls):
        '''
        Add a node to the topology
        '''
        if name in self.nodes:
            raise Exception("A node by the name {} already exists.  Can't add a duplicate.".format(name))
        self.__nxgraph.add_node(name)
        self.__nxgraph.node[name]['label'] = name
        self.__nxgraph.node[name]['nodeobj'] = cls()

    @property
    def nodes(self):
        return self.__nxgraph.nodes(data=True)

    @property
    def links(self):
        return self.__nxgraph.edges(data=True)

    def addHost(self, name=None):
        '''
        Add a new host node to the topology.
        '''
        if name is None:
            name = 'h' + str(self.__hnum)
            self.__hnum += 1
        self.__addNode(name, Host)
        return name

    def addSwitch(self, name=None):
        '''
        Add a new switch to the topology.
        '''
        if name is None:
            name = 's' + str(self.__snum)
            self.__snum += 1
        self.__addNode(name, Switch)
        return name

    def addRouter(self, name=None):
        '''
        Add a new switch to the topology.
        '''
        if name is None:
            name = 'r' + str(self.__rnum)
            self.__rnum += 1
        self.__addNode(name, Router)
        return name

    def addLink(self, node1, node2, capacity, delay):
        '''
        Add a bidirectional link between node1 and node2 with the given
        capacity and delay to the topology.
        '''
        for n in (node1, node2):
            if not self.__nxgraph.has_node(n):
                raise Exception("No node {} exists for building a link".format(n))
        node1if = self.__nxgraph.node[node1]['nodeobj'].addInterface()
        node2if = self.__nxgraph.node[node2]['nodeobj'].addInterface()
        self.__nxgraph.add_edge(node1, node2)
        self.__nxgraph[node1][node2]['label'] = "{} {}".format(humanize_capacity(capacity), humanize_delay(delay))
        self.__nxgraph[node1][node2]['capacity'] = unhumanize_capacity(capacity)
        self.__nxgraph[node1][node2]['delay'] = unhumanize_delay(delay)
        self.__nxgraph[node1][node2][node1] = node1if
        self.__nxgraph[node1][node2][node2] = node2if

    def serialize(self):
        '''
        Return a JSON string of the serialized topology
        '''
        return json.dumps(json_graph.node_link_data(self.__nxgraph), cls=Encoder)

    @staticmethod
    def unserialize(jsonstr):
        '''
        Unserialize a JSON string representation of a topology
        '''
        topod = json.loads(jsonstr)
        G = json_graph.node_link_graph(topod)
        for n,ndict in G.nodes(data=True):
            print (n,ndict)
            if 'nodeobj' not in ndict:
                raise Exception("Required nodetype information is not present in serialized node {} :{}".format(n, ndict))
            nobj = ndict['nodeobj']
            cls = eval(nobj['nodetype'])
            print (nobj['nodetype'], cls)
            ndict['nodeobj'] = cls(**dict(ndict))
        t = Topology(nxgraph=G)
        return t

    def __str__(self):
        return self.serialize()

    def __autoAssignAddresses(self):
        pass

