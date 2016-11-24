import unittest
from unittest.mock import Mock

import switchyard.lib.socket.socketemu as sock
from switchyard.lib.packet import IPProtocol

class LLNetDevTests(unittest.TestCase):
    def setUp(self):
        self.firemock = Mock()
        self.firemock.add_rule = Mock()
        self.pcapmock = Mock()
        self.pcapmock.set_bpf_filter_on_all_devices = Mock()
        setattr(sock, "Firewall", self.firemock)
        setattr(sock, "PcapLiveDevice", self.pcapmock)

    def testEphemeral(self):
        p = sock._get_ephemeral_port()
        xset = sock._gather_ports() 
        self.assertNotIn(p, xset)

    def testSockCreate(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertEqual(s._protoname, 'udp')
        self.assertEqual(s._proto, IPProtocol.UDP)
        localport = s._local_addr[1]

        self.firemock.add_rule.assert_called_with('udp:{}'.format(localport))
        self.pcapmock.set_bpf_filter_on_all_devices.assert_called_with('udp dst port {} or icmp'.format(localport))

if __name__ == '__main__':
    unittest.main()
