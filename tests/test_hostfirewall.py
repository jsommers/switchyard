import sys
import unittest

import switchyard.hostfirewall as hf

class HostFirewallTests(unittest.TestCase):
    def _collectcmd2(self, args, cmdlist):
        self.cmds.append( (args,cmdlist) )
        return True,""

    def _collectcmd1(self, cmd):
        self.cmds.append( (cmd,) )
        rv = ""
        if cmd == "pfctl -E":
            rv = "Token: 0"
        return True,rv

    def setUp(self):
        self.cmds = []
        setattr(hf, "_sendcmd", self._collectcmd2)
        setattr(hf, "getstatusoutput", self._collectcmd1)
        hf.Firewall._instance = None

    def testLinux(self):
        setattr(sys, "platform", "linux")
        fw = hf.Firewall(("eth0",), ("icmp:*","tcp:80"))
        fw.__enter__()
        self.assertEqual(self.cmds[-2], ('iptables -t raw -P PREROUTING DROP --protocol icmp -i eth0 --port *',))
        self.assertEqual(self.cmds[-1], ('iptables -t raw -P PREROUTING DROP --protocol tcp -i eth0 --port 80',))
        fw.add_rule("udp:123")
        self.assertEqual(self.cmds[-3], ('iptables -t raw -P PREROUTING DROP --protocol icmp -i eth0 --port *',))
        self.assertEqual(self.cmds[-2], ('iptables -t raw -P PREROUTING DROP --protocol tcp -i eth0 --port 80',))
        self.assertEqual(self.cmds[-1], ('iptables -t raw -P PREROUTING DROP --protocol udp -i eth0 --port 123',))

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

    def testTest(self):
        setattr(sys, "platform", "test")
        fw = hf.Firewall(("eth0",), ("icmp:*","tcp:80"))
        fw.__enter__()
        self.assertEqual(self.cmds, [])
        

if __name__ == '__main__':
    unittest.main()

