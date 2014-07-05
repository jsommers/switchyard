import json
from collections import defaultdict
from switchyard.lib.address import EthAddr,IPAddr

class Interface(object):
    '''
    Class that models a single logical interface on a network
    device.  An interface has a name, 48-bit Ethernet MAC address,
    and a 32-bit IPv4 address and mask.
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
        return "{} mac:{} ip:{}/{}".format(str(self.name), str(self.ethaddr), str(self.ipaddr), str(self.netmask))


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
        return str(self.asDict())

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
    __slots__ = ['__name','__nodes','__links','__hnum','__snum','__rnum']
    def __init__(self, name="No name topology"):
        self.__name = name
        self.__nodes = {}
        self.__links = defaultdict(dict)
        self.__hnum = 0
        self.__snum = 0
        self.__rnum = 0

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    def __addNode(self, name, cls):
        '''
        Add a node to the topology
        '''
        if name in self.nodes:
            raise Exception("A node by the name {} already exists.  Can't add a duplicate.".format(name))
        self.nodes[name] = cls()

    @property
    def nodes(self):
        return self.__nodes

    @nodes.setter
    def nodes(self, value):
        self.__nodes = value

    @property
    def links(self):
        return self.__links

    @links.setter
    def links(self, value):
        self.__links = value

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
            if n not in self.nodes:
                raise Exception("No node {} exists for building a link".format(n))
        node1if = self.nodes[node1].addInterface()
        node2if = self.nodes[node2].addInterface()
        linkdict = {'capacity':capacity, 'delay':delay, node1:node1if, node2:node2if}
        self.links[node1][node2] = linkdict
        self.links[node2][node1] = linkdict

    def serialize(self):
        '''
        Return a JSON string of the serialized topology
        '''
        return json.dumps({'nodes':self.nodes, 'links':self.links, 'name':self.name}, cls=Encoder)

    @staticmethod
    def unserialize(jsonstr):
        '''
        Unserialize a JSON string representation of a topology
        '''
        topod = json.loads(jsonstr)
        t = Topology()
        if 'links' not in topod:
            raise Exception("No links found in topology")
        if 'nodes' not in topod:
            raise Exception("No links found in topology")
        if 'name' not in topod:
            print ("No name found in topology; defaulting to 'No name'")
            t.name = 'No name'
        else:
            t.name = topod['name']
        t.nodes = topod['nodes']
        t.links = topod['links']
        xnodes = {}
        for nname,ndict in t.nodes.items():
            if 'nodetype' not in ndict:
                raise Exception("Required nodetype information is not present in serialized node {} :{}".format(nodename, ndict))
            cls = ndict['nodetype']
            xnodes[nname] = eval(cls)(**dict(ndict))
        t.nodes = xnodes
        return t

    def __str__(self):
        return self.serialize()

    def __autoAssignAddresses(self):
        pass

