import sys
import unittest

import switchyard.hostfirewall as hf

class HostFirewallTests(unittest.TestCase):
    def _collectcmd(self, cmd, stdin=None):
        self.cmds.append( (cmd,stdin) )
        rv = ""
        if cmd == "/sbin/pfctl -E":
            rv = "Token: 0"
        return True,rv

    def setUp(self):
        self.cmds = []
        setattr(hf, "_runcmd", self._collectcmd)
        hf.Firewall._instance = None

    def testErrorInit(self):
        hf.Firewall(("eth0",), ("icmp:*","tcp:80"))
        with self.assertRaises(Exception):
            hf.Firewall(("eth0",), ("icmp:*","tcp:80"))
        setattr(sys, "platform", "vax/vms")
        hf.Firewall._instance = None
        with self.assertRaises(Exception):
            hf.Firewall(("eth0",), ("icmp:*","tcp:80"))

    def testLinux(self):
        setattr(sys, "platform", "linux")
        fw = hf.Firewall(("eth0",), ("icmp:*","tcp:80"))
        fw.__enter__()
        cmds = ['/sbin/iptables-save',
        '/sbin/iptables -F',
        '/sbin/iptables -t raw -F', 
        '/sbin/iptables -t raw -A PREROUTING -j DROP --protocol icmp -i eth0',
        '/sbin/iptables -t raw -A PREROUTING -j DROP --protocol tcp -i eth0 --dport 80']

        xcmds = [ c for c,inp in self.cmds]
        self.assertEqual(cmds, xcmds)
        fw.add_rule("udp:123")
        cmds = ['/sbin/iptables-save', 
        '/sbin/iptables -F', 
        '/sbin/iptables -t raw -F',
        '/sbin/iptables -t raw -A PREROUTING -j DROP --protocol icmp -i eth0',
        '/sbin/iptables -t raw -A PREROUTING -j DROP --protocol tcp -i eth0 --dport 80',
        '/sbin/iptables -t raw -A PREROUTING -j DROP --protocol udp -i eth0 --dport 123']
        xcmds = [ c for c,inp in self.cmds]
        self.assertEqual(cmds, xcmds)
        fw.__exit__(0,0,0)

    def testLinux2(self):
        setattr(sys, "platform", "linux")
        fw = hf.Firewall(("eth0","eth1"), ("all",))
        fw.__enter__()
        cmds = ['/sbin/iptables-save',
                '/sbin/sysctl net.ipv4.conf.eth0.arp_ignore',
                '/sbin/sysctl net.ipv4.conf.eth1.arp_ignore',
                '/sbin/iptables -F',
                '/sbin/iptables -t raw -F',
                '/sbin/iptables -t raw -A PREROUTING -j DROP -i eth0',
                '/sbin/iptables -t raw -A PREROUTING -j DROP -i eth1',]
        xcmds = [ c for c,inp in self.cmds]
        self.assertEqual(cmds, xcmds)
        fw.__exit__(0,0,0)

    def testLinux3(self):
        setattr(sys, "platform", "linux")
        fw = hf.Firewall(("eth0","eth1"), ("none",))
        fw.__enter__()
        cmds = ['/sbin/iptables-save',
                '/sbin/iptables -F',
                '/sbin/iptables -t raw -F' ]
        xcmds = [ c for c,inp in self.cmds]
        self.assertEqual(cmds, xcmds)
        fw.__exit__(0,0,0)

    def testMacos(self):
        setattr(sys, "platform", "darwin")
        fw = hf.Firewall(("eth0",), ("icmp:*","tcp:80"))
        fw.__enter__()
        rules = self.cmds[1][1]
        self.assertEqual(rules[0], 'block drop on eth0 proto icmp from any to any')
        self.assertEqual(rules[1], 'block drop on eth0 proto tcp from any port 80 to any port 80')
        fw.add_rule("udp:123")
        rules = self.cmds[1][1]
        self.assertEqual(rules[0], 'block drop on eth0 proto icmp from any to any')
        self.assertEqual(rules[1], 'block drop on eth0 proto tcp from any port 80 to any port 80')
        self.assertEqual(rules[2], 'block drop on eth0 proto udp from any port 123 to any port 123')
        fw.__exit__(0,0,0)

    def testBadRule1(self):
        setattr(sys, "platform", "test")
        with self.assertRaises(ValueError):
            fw = hf.Firewall(("eth0",), ("mpxyz",))

    def testBadRule2(self):
        setattr(sys, "platform", "test")
        with self.assertRaises(ValueError):
            fw = hf.Firewall(("eth0",), ("xicmp:asdf",))

    def testTest(self):
        setattr(sys, "platform", "test")
        fw = hf.Firewall(("eth0",), ("all", "none", "icmp:*","tcp:80"))
        fw.__enter__()
        self.assertEqual(self.cmds, [])
        fw.add_rule("udp:123")
        self.assertEqual(self.cmds, [])
        self.assertEqual(
            [('all', None), ('none', None), ('icmp', None), ('tcp', '80'), ('udp', '123')],
            hf.Firewall._instance._firewall_delegate._rules)
        fw.__exit__(0,0,0)
        

if __name__ == '__main__':
    unittest.main()

