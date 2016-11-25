import unittest
from unittest.mock import Mock
from queue import Queue

import switchyard.lib.socket.socketemu as sock
from switchyard.lib.packet import IPProtocol

class SocketEmuTests(unittest.TestCase):
    def setUp(self):
        sock.ApplicationLayer.init()
        sock.ApplicationLayer._to_app = {}
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
        self.assertEqual(s.family, sock.AF_INET)
        self.assertEqual(s.type, sock.SOCK_DGRAM)
        self.assertEqual(s.proto, IPProtocol.UDP)
        localport = s._local_addr[1]
        self.assertEqual(len(sock.ApplicationLayer._to_app), 1)
        self.assertIn((sock.AF_INET, IPProtocol.UDP, '0.0.0.0', localport), sock.ApplicationLayer._to_app)

        self.firemock.add_rule.assert_called_with('udp:{}'.format(localport))
        self.pcapmock.set_bpf_filter_on_all_devices.assert_called_with('udp dst port {} or icmp or icmp6'.format(localport))

        self.assertEqual(len(sock.ApplicationLayer._to_app), 1)
        self.assertIsInstance(sock.ApplicationLayer._from_app, Queue)

        with self.assertRaises(NotImplementedError):
            sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        with self.assertRaises(NotImplementedError):
            sock.socket(sock.AF_INET, sock.SOCK_RAW)
        s.close()
        self.assertEqual(len(sock.ApplicationLayer._to_app), 0)

    def testSockBind(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        localport = s._local_addr[1]
        self.assertEqual(s._protoname, 'tcp')
        self.firemock.add_rule.assert_called_with('tcp:{}'.format(localport))
        self.pcapmock.set_bpf_filter_on_all_devices.assert_called_with('tcp dst port {} or icmp or icmp6'.format(localport))
        s.bind(('10.1.1.1', 5555))
        self.firemock.add_rule.assert_called_with('tcp:{}'.format(5555))
        self.pcapmock.set_bpf_filter_on_all_devices.assert_called_with('tcp dst port {} or icmp or icmp6'.format(5555))

    def testDefaults(self):
        self.assertEqual(sock.getdefaulttimeout(), 1.0)
        sock.setdefaulttimeout(2.0)
        self.assertEqual(sock.getdefaulttimeout(), 2.0)
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertEqual(s._timeout, 2.0)



if __name__ == '__main__':
    unittest.main()
