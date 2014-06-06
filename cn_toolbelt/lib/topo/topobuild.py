import json
import sys
import os
import os.path
from collections import defaultdict
sys.path.append(os.getcwd())
from cn_toolbelt.switchyard.switchy_common import Interface

class Node(object):
    __slots__ = ['ifnum','__interfaces']
    def __init__(self, *args, **kwargs):
        self.ifnum = 0
        self.__interfaces = {}

    @property
    def interfaces(self):
        return self.__interfaces

    def addInterface(self, ethaddr=None, ipaddr=None, netmask=None):
        ifname = 'eth{}'.format(self.ifnum)
        self.ifnum += 1
        intf = Interface(ifname, ethaddr, ipaddr, netmask)
        self.__interfaces[ifname] = intf
        return ifname

    def asDict(self):
        tmp = dict(self.__interfaces)
        tmp['nodetype'] = self.__class__.__name__
        return tmp

class Host(Node):
    def __init__(self, *args, **kwargs):
        Node.__init__(self, *args, **kwargs)

    def __repr__(self):
        return 'Host'

class Switch(Node):
    def __init__(self, *args, **kwargs):
        Node.__init__(self, *args, **kwargs)

    def __repr__(self):
        return 'Switch'

class Router(Node):
    def __init__(self, *args, **kwargs):
        Node.__init__(self, *args, **kwargs)

    def __repr__(self):
        return 'Router'

class Encoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs):
        json.JSONEncoder.__init__(self, *args, **kwargs)

    def default(self, o):
        return {'nodetype':o.__class__.__name__}

class Topology(object):
    def __init__(self, name="No name topology"):
        self.name = name
        self.nodes = {}
        self.links = defaultdict(dict)
        self.__hnum = 0
        self.__snum = 0
        self.__rnum = 0

    def __addNode(self, name, cls):
        '''
        Add a node to the topology
        '''
        if name in self.nodes:
            raise Exception("A node by the name {} already exists.  Can't add a duplicate.".format(name))
        self.nodes[unicode(name)] = cls()

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
            print "No name found in topology; defaulting to 'No name'"
            t.name = 'No name'
        else:
            t.name = topod['name']
        t.nodes = topod['nodes']
        t.links = topod['links']
        xnodes = {}
        for nname,ndict in t.nodes.iteritems():
            if 'nodetype' not in ndict:
                raise Exception("Required nodetype information is not present in serialized node {} :{}".format(nodename, ndict))
            cls = ndict['nodetype']
            xnodes[nname] = eval(cls)(ndict)
        t.nodes = xnodes
        return t

    def __str__(self):
        return self.serialize()

    def __autoAssignAddresses(self):
        pass


import unittest
class TestTopo(unittest.TestCase):
    def test_serunser(self):
        t = Topology()
        h1 = t.addHost()
        h2 = t.addHost()
        s1 = t.addSwitch()
        t.addLink(h1, s1, 10000000, 0.05)
        t.addLink(h2, s1, 10000000, 0.05)

        x = t.serialize()
        tprime = Topology.unserialize(x)
        y = t.serialize()

        self.assertItemsEqual(t.nodes.keys(), tprime.nodes.keys())
        # No can do: no ordering for node-class objects
        # self.assertItemsEqual(t.nodes.values(), tprime.nodes.values())
        self.assertItemsEqual(t.links.keys(), tprime.links.keys())
        self.assertItemsEqual(t.links.values(), tprime.links.values())


if __name__ == '__main__':
    unittest.main()
