from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.topo.util import *
from switchyard.lib.topo.topobuild import *
import switchyard.lib.interface as intfmod
import unittest 
from unittest.mock import Mock

class TopologyTests(unittest.TestCase):
    def testHumanizeCap(self):
        self.assertEqual(humanize_bandwidth(100), "100 bits/s")
        self.assertEqual(humanize_bandwidth(1000), "1 Kb/s")
        self.assertEqual(humanize_bandwidth(10000), "10 Kb/s")
        self.assertEqual(humanize_bandwidth(150000), "150 Kb/s")
        self.assertEqual(humanize_bandwidth(1500000), "1.5 Mb/s")
        self.assertEqual(humanize_bandwidth(10000000), "10 Mb/s")
        self.assertEqual(humanize_bandwidth(100000000), "100 Mb/s")
        self.assertEqual(humanize_bandwidth(900000000), "900 Mb/s")
        self.assertEqual(humanize_bandwidth(1000000000), "1 Gb/s")
        self.assertEqual(humanize_bandwidth(100000000000), "100 Gb/s")
        self.assertEqual(humanize_bandwidth(2000000000000), "2 Tb/s")
        with self.assertRaises(Exception):
            humanize_bandwidth(1e20)

    def testUnhumanizeCap(self):
        self.assertEqual(unhumanize_bandwidth("100 bits/s"), 100)
        self.assertEqual(unhumanize_bandwidth("1 Kb/s"), 1000)
        self.assertEqual(unhumanize_bandwidth("1 KB/s"), 8000)
        self.assertEqual(unhumanize_bandwidth("  1  KByte per sec"), 8000)
        self.assertEqual(unhumanize_bandwidth("  1.0  KByte per sec"), 8000)
        self.assertEqual(unhumanize_bandwidth("10 Kb/s"), 10000)
        self.assertEqual(unhumanize_bandwidth("150 Kb/s"), 150000)
        self.assertEqual(unhumanize_bandwidth("1.5 Mb/s"), 1500000)
        self.assertEqual(unhumanize_bandwidth("10 Mb/s"),  10000000)
        self.assertEqual(unhumanize_bandwidth("100 Mb/s"), 100000000)
        self.assertEqual(unhumanize_bandwidth("900 Mb/s"), 900000000)
        self.assertEqual(unhumanize_bandwidth("1 Gb/s"),    1000000000)
        self.assertEqual(unhumanize_bandwidth("100 Gb/s"),100000000000)
        self.assertEqual(unhumanize_bandwidth("2 Tb/s"), 2000000000000)
        self.assertEqual(unhumanize_bandwidth("100000"), 100000)
        self.assertEqual(unhumanize_bandwidth("100000  "), 100000)
        self.assertEqual(unhumanize_bandwidth(10000), 10000)
        self.assertIsNone(unhumanize_bandwidth(" xyz"))
        
    def testHumanizeDelay(self):
        self.assertEqual(humanize_delay(0.1), "100 msecs")
        self.assertEqual(humanize_delay(0.01), "10 msecs")
        self.assertEqual(humanize_delay(0.001), "1 msec")
        self.assertEqual(humanize_delay(0.002), "2 msecs")
        self.assertEqual(humanize_delay(0.0002), "200 \u00B5secs")
        self.assertEqual(humanize_delay(1), "1 sec")
        self.assertEqual(humanize_delay(1.5), "1500 msecs")
        self.assertEqual(humanize_delay(0.00000001), "1e-08 sec")

    def testUnhumanizeDelay(self):
        self.assertEqual(unhumanize_delay("100 milliseconds"), 0.1)
        self.assertEqual(unhumanize_delay("10 milliseconds"), 0.01)
        self.assertEqual(unhumanize_delay("1 millisecond"), 0.001)
        self.assertEqual(unhumanize_delay("2 milliseconds"), 0.002)
        self.assertEqual(unhumanize_delay("200 microseconds"), 0.0002)
        self.assertEqual(unhumanize_delay("1 second"), 1)
        self.assertEqual(unhumanize_delay("1.5 seconds"), 1.5)
        self.assertEqual(unhumanize_delay("0.1"), 0.1)
        self.assertEqual(unhumanize_delay(0.1), 0.1)
        self.assertIsNone(unhumanize_delay("ab.32"))
        self.assertIsNone(unhumanize_delay("1 picosec"))

    def testTopoBuild(self):
        t = Topology()
        t.addHost('h1')
        t.addHost('h2')
        t.addRouter('r1')
        t.addSwitch('s1')
        t.addLink('h1','r1','1 Mb/s','5 milliseconds')
        t.addLink('h1','s1','1 Mb/s','5 milliseconds')
        t.addLink('h2','r1','1 Mb/s','5 milliseconds')
        t.addLink('h2','s1','1 Mb/s','5 milliseconds')
        self.assertTrue(t.auto_macs)
        self.assertIn("h1", t)
        with self.assertRaises(Exception):
            t.addHost("h1")
        self.assertTrue(t.hasEdge("h1", "r1"))
        self.assertFalse(t.hasEdge("h1", "h2"))
        self.assertListEqual(sorted(t.nodes), sorted(['h1','h2','r1','s1']))
        self.assertListEqual(t.routers, ['r1'])
        self.assertListEqual(t.switches, ['s1'])
        self.assertListEqual(sorted(t.hosts), ['h1','h2'])
        self.assertListEqual(sorted([ sorted(tup) for tup in t.links]), sorted([['h1','r1'],['h1','s1'],['h2','r1'],['h2','s1']]))

        self.assertIsInstance(t.getNode('h1'), dict)
        self.assertIsInstance(t.getLink('h1','s1'), dict)

        with self.assertRaises(KeyError):
            t.getNode('x1')
        with self.assertRaises(KeyError):
            t.getLink('h1','x1')
        with self.assertRaises(KeyError):
            t.getLink('x1','h1')

        self.assertListEqual(sorted(t.neighbors('h1')), ['r1','s1'])
        self.assertListEqual(sorted(t.edges_from('h1')), [('h1','r1'),('h1','s1')])
        nobj = t.getNode('h1')['nodeobj']
        self.assertEqual(len(nobj.interfaces), 2)
        self.assertEqual(str(nobj.interfaces['eth0'].ethaddr), '00:00:00:00:00:01')
        self.assertEqual(str(nobj.interfaces['eth1'].ethaddr), '00:00:00:00:00:03')
        self.assertTrue(str(nobj).startswith("Host eth0 "))

        t.assignIPAddresses(prefix='192.168.1.0/24')
        self.assertEqual(str(nobj.interfaces['eth0'].ipaddr)[:-1], "192.168.1.")
        self.assertEqual(str(nobj.interfaces['eth0'].netmask), "255.255.255.0")

        h1ifname,r1ifname = t.getLinkInterfaces('h1','r1')
        self.assertEqual(h1ifname, 'eth0')
        self.assertEqual(r1ifname, 'eth0')
        t.setInterfaceAddresses('h1',h1ifname,ip="10.0.1.1",netmask="255.255.0.0",mac="11:22:33:44:55:66") 
        ethaddr,ip,mask = t.getInterfaceAddresses('h1',h1ifname)
        self.assertEqual(ethaddr,EthAddr("11:22:33:44:55:66"))
        self.assertEqual(ip,IPAddr("10.0.1.1"))
        self.assertEqual(mask,IPAddr("255.255.0.0"))

        t.removeLink('h1', 'r1')
        self.assertFalse(t.hasEdge('h1', 'r1'))
        with self.assertRaises(Exception):
            t.setLinkCharacteristics('h1', 'r1', capacity="10Mbps")

        t.assignIPAddresses()
        n = t.getNode('h2')
        nobj = n['nodeobj']
        self.assertRegex(str(nobj), "\s+ip:10\.0\.0\.\d\/8\s+")

        with self.assertRaises(Exception):
            t.setInterfaceAddresses('h42', 'eth0')
        with self.assertRaises(Exception):
            t.setInterfaceAddresses('h2', 'eth99')

    def testTopoCompose(self):
        t1 = Topology('A')
        t1.addHost('h1')
        t1.addSwitch('s1')
        t1.addHost('h2')
        t1.addLink('h1','s1','100Mb/s', '50 ms')
        t1.addLink('h2','s1','100Mb/s', '50 ms')
        t2 = Topology('B')
        t2.addHost('h1')
        t2.addRouter('r1')
        t2.addHost('h2')
        t2.addLink('h1','r1','100Mb/s', '50 ms')
        t2.addLink('h2','r1','100Mb/s', '50 ms')
        t1.addNodeLabelPrefix("A")
        self.assertListEqual(sorted(t1.nodes), sorted(['A_h1','A_h2','A_s1']))
        self.assertListEqual(sorted([sorted(x) for x in t1.links]), sorted([sorted(x) for x in [('A_s1','A_h1'),('A_s1','A_h2')]]))
        t2.addNodeLabelPrefix("B")
        t3 = t1.union(t2)
        t3.addLink('B_r1','A_s1','1Gb/s',0.1)
        self.assertListEqual(sorted(t3.nodes), sorted(['A_h1','A_h2','A_s1','B_h1','B_h2','B_r1']))
        self.assertListEqual(sorted([sorted(x) for x in t3.links]), sorted([sorted(x) for x in [('A_h1', 'A_s1'), ('B_h1', 'B_r1'), ('A_h2', 'A_s1'), ('B_r1', 'A_s1'), ('B_r1', 'B_h2')]]))
        t3.addRouter()
        self.assertListEqual(sorted(t3.nodes), sorted(['A_h1','A_h2','A_s1','B_h1','B_h2','B_r1','r0']))
        self.assertEqual(t1.name, "A")
        t1.name = "B"
        self.assertEqual(t1.name, "B")

    def testTopoAddRemove(self):
        t1 = Topology('A')
        t1.addHost('h1')
        t1.addSwitch('s1')
        t1.addHost('h2')
        t1.addLink('h1','s1','100Mb/s', '50 ms')
        t1.addLink('h2','s1','1Gb', '0.1 sec')
        self.assertListEqual(sorted(t1.nodes), sorted(['h1','h2','s1']))
        self.assertListEqual(sorted([sorted(x) for x in t1.links]), sorted([sorted(x) for x in [('s1','h1'),('s1','h2')]]))
        # removal of central switch should remove both incident links
        t1.removeNode('s1')
        self.assertListEqual(sorted(t1.nodes), sorted(['h1','h2']))
        self.assertListEqual(t1.links, [])

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
        self.assertEqual(x,y)

    def testNodeIfRebuild(self):
        d = {"eth0": "eth0 mac:00:00:00:00:00:18 ip:192.168.3.3/24"}
        r = Router(interfaces=d)
        self.assertTrue(r.hasInterface('eth0'))
        self.assertEqual(r.nodetype, 'Router')
        self.assertEqual(r.getInterface('eth0').ethaddr, EthAddr("00:00:00:00:00:18"))
        self.assertEqual(r.getInterface('eth0').ipaddr, IPv4Address("192.168.3.3"))
        self.assertEqual(r.getInterface('eth0').netmask, IPv4Address("255.255.255.0"))

        d = {"eth0": "eth0 mac:00:00:00:00:00:18" }
        r = Router(interfaces=d)
        self.assertEqual(r.getInterface('eth0').ethaddr, EthAddr("00:00:00:00:00:18"))
        self.assertEqual(r.getInterface('eth0').ipaddr, IPv4Address("0.0.0.0"))
        self.assertEqual(r.getInterface('eth0').netmask, IPv4Address("255.255.255.255"))
        rdict = r.asDict()
        self.assertEqual(rdict['interfaces'], d)

    def testInterface(self):
        intf = intfmod.Interface("test", None, None, None)
        self.assertTrue(str(intf).startswith("test"))
        self.assertTrue("mac:00:00:00:00:00:00" in str(intf))
        intf.ethaddr = EthAddr("00:11:22:33:44:55")
        self.assertEqual(str(intf.ethaddr), "00:11:22:33:44:55")
        intf.ethaddr = None
        self.assertTrue("mac:00:00:00:00:00:00" in str(intf))
        with self.assertRaises(Exception):
            intf.ipaddr = 1
        intf.ipaddr = "1.2.3.4"
        intf.netmask = "24"
        self.assertTrue("ip:1.2.3.4/24" in str(intf))
        intf.netmask = "255.255.252.0"
        self.assertTrue("ip:1.2.3.4/22" in str(intf))
        with self.assertRaises(Exception):
            intf.netmask = True
        with self.assertRaises(Exception):
            intf.ethaddr = True
        intf.ethaddr = b'\x01\x02\x03\x04\x05\x06'
        self.assertEqual(intf.ethaddr, EthAddr("01:02:03:04:05:06"))
        intf.ipaddr = "9.8.7.6"
        intf.netmask = None
        self.assertEqual(intf.ipaddr, IPv4Address("9.8.7.6"))
        self.assertEqual(str(intf.ipinterface), "9.8.7.6/32")
        with self.assertRaises(Exception):
            intf.netmask = 4.5
        self.assertEqual(intf.iftype, intfmod.InterfaceType.Unknown)
        with self.assertRaises(Exception):
            intf.iftype = intfmod.InterfaceType.Wireless

    def testDevListMaker(self):
        import switchyard.pcapffi as pf
        import socket as sock

        # name, intname, desc, loop, up, running
        dlist = [
            pf.PcapInterface("a", "aint", "", False, True, True),
        ]
        devmock = Mock(return_value=dlist)
        ifnum = Mock(side_effect=range(0,100))
        setattr(intfmod, "pcap_devices", devmock)
        setattr(intfmod, "if_nametoindex", ifnum)
        # includes, excludes
        rv = intfmod.make_device_list(set({"a"}), set())
        self.assertEqual(len(rv), 1)
        self.assertIn("a", rv)
        rv = intfmod.make_device_list(set(), set())
        self.assertEqual(len(rv), 1)
        self.assertIn("a", rv)
        rv = intfmod.make_device_list(set(), set({"a"}))
        self.assertEqual(len(rv), 0)
        rv = intfmod.make_device_list(set({"xyz"}), set({"a"}))
        self.assertEqual(len(rv), 0)
        dlist = [
            pf.PcapInterface("a", "aint", "", False, True, True),
            pf.PcapInterface("b", "bint", "", True, True, True),
            pf.PcapInterface("c", "cint", "", False, True, True),
        ]
        devmock = Mock(return_value=dlist)
        setattr(intfmod, "pcap_devices", devmock)

        rv = intfmod.make_device_list(includes=set({"xyz"}), excludes=set({"a"}))
        self.assertEqual(len(rv), 1)
        self.assertIn("c", rv)
        
        rv = intfmod.make_device_list(excludes=set({"a"}))
        self.assertEqual(len(rv), 1)
        self.assertIn("c", rv)

        ifnum = Mock(side_effect=Exception)
        setattr(intfmod, "if_nametoindex", ifnum)
        rv = intfmod.make_device_list(includes=set(), excludes=set())
        self.assertEqual(len(rv), 0)


if __name__ == '__main__':
        unittest.main()
