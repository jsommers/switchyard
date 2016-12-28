import unittest 
import os
import sys
from unittest.mock import Mock

from switchyard.lib.packet import *
import switchyard.pcapffi as pf

class PcapFfiTests(unittest.TestCase):
    def testWriteRead(self):
        dump = pf.PcapDumper("testXX.pcap")
        pkt = Ethernet() + IPv6() + ICMPv6()
        pkt[0].ethertype = EtherType.IPv6
        pkt[1].nextheader = IPProtocol.ICMPv6
        with self.assertRaises(pf.PcapException):
            dump.write_packet(pkt)
        dump.write_packet(pkt.to_bytes())
        dump.close()

        reader = pf.PcapReader("testXX.pcap")
        count = 0
        while True:
            p = reader.recv_packet()
            if not p:
                break
            count += 1
            if count == 1:
                rpkt = Packet(raw=p.raw)
                self.assertEqual(pkt, rpkt)
        reader.close()
        self.assertEqual(count, 1)
        os.unlink("testXX.pcap")

    def testLowLevel(self):
        with self.assertRaises(Exception):
            pf._PcapFfi()
        xffi = pf._PcapFfi._instance._ffi
        xlibpcap = pf._PcapFfi._instance._libpcap
        pf._PcapFfi._instance._ffi = Mock()
        pf._PcapFfi._instance._libpcap = Mock()
        pf._PcapFfi._instance._libpcap.pcap_setnonblock = Mock(return_value=0)
        pf._PcapFfi._instance._libpcap.pcap_getnonblock = Mock(return_value=1)
        pf._PcapFfi._instance._libpcap.pcap_snapshot = Mock(return_value=1972)
        pf._PcapFfi._instance._libpcap.pcap_datalink = Mock(return_value=13)

        with self.assertRaises(Exception):
            pf._PcapFfi._instance.discoverdevs()

        devs = pf.pcap_devices()
        if len(devs):
            self.assertIsInstance(devs[0], pf.PcapInterface)
            xname = devs[0].name
            with self.assertRaises(pf.PcapException):
                pf._PcapFfi._instance.open_live(xname)
            pf._PcapFfi._instance._libpcap.pcap_datalink = Mock(return_value=0)
            pcapx = pf._PcapFfi._instance.open_live(xname)
            self.assertEqual(pcapx.dlt, pf.Dlt.DLT_NULL)
            self.assertEqual(pcapx.snaplen, 1972)
            self.assertEqual(pcapx.nonblock, 1)

            pf._PcapFfi._instance._libpcap.pcap_sendpacket = Mock(return_value=0)
            with self.assertRaises(pf.PcapException):
                pf._PcapFfi._instance.send_packet(pcapx, Packet())
            rv = pf._PcapFfi._instance.send_packet(pcapx, b'\xbe\xef')
            self.assertTrue(rv)
            pf._PcapFfi._instance._libpcap.pcap_geterr = Mock(return_value="fake error")
            pf._PcapFfi._instance._libpcap.pcap_sendpacket = Mock(return_value=-1)
            with self.assertRaises(pf.PcapException):
                rv = pf._PcapFfi._instance.send_packet(pcapx, b'\xbe\xef')
                
        livedev = pf.PcapLiveDevice("en0")
        self.assertEqual(len(pf.PcapLiveDevice._OpenDevices), 1)
        self.assertIn("en0", pf.PcapLiveDevice._OpenDevices)
        pf._PcapFfi._instance._libpcap.pcap_sendpacket = Mock(return_value=0)
        self.assertIsNone(livedev.send_packet(b'\x00'))

        livedev.close()
        self.assertEqual(len(pf.PcapLiveDevice._OpenDevices), 0)

        pf._PcapFfi._instance._ffi = xffi
        pf._PcapFfi._instance._libpcap = xlibpcap

if __name__ == '__main__':
    unittest.main()
