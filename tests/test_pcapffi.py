import unittest 
import os
import sys
from unittest.mock import Mock

from switchyard.lib.packet import *
import switchyard.pcapffi as pf

class PcapFfiTests(unittest.TestCase):
    def testWriteRead1(self):
        dump = pf.PcapDumper("testXX.pcap")
        pkt = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00\x1c\x00\x00\x00\x00\x00\x01\xba\xe2\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xf7\xff\x00\x00\x00\x00'
        dump.write_packet(pkt)
        with self.assertRaises(pf.PcapException):
            dump.write_packet("hello, world")
        dump.close()

        reader = pf.PcapReader("testXX.pcap")
        reader.set_filter("icmp")
        pkts = []
        while True:
            p = reader.recv_packet()
            if p is None:
                break
            pkts.append(p)
        reader.close()
        self.assertEqual(len(pkts), 1)
        self.assertEqual(pkts[0].capture_length, len(pkt))
        self.assertEqual(pkts[0].length, len(pkt))
        self.assertEqual(pkts[0].raw, pkt)
        os.unlink("testXX.pcap")

    def testWriteRead2(self):
        dump = pf.PcapDumper("testXX.pcap")
        pkt = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00\x1c\x00\x00\x00\x00\x00\x01\xba\xe2\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xf7\xff\x00\x00\x00\x00'
        dump.write_packet(pkt)
        with self.assertRaises(pf.PcapException):
            dump.write_packet("hello, world")
        dump.close()

        reader = pf.PcapReader("testXX.pcap")
        reader.set_filter("tcp")
        pkts = []
        while True:
            p = reader.recv_packet()
            if p is None:
                break
            pkts.append(p)
        reader.close()
        self.assertEqual(len(pkts), 0)
        os.unlink("testXX.pcap")

    def testAnotherInstance(self):
        with self.assertRaises(Exception):
            pf._PcapFfi()

        with self.assertRaises(Exception):
            pf._PcapFfi._instance.discoverdevs()

    def testCreate(self):
        devs = pf.pcap_devices()
        xname = devs[0].name
        px = pf.PcapLiveDevice.create(xname)
        px.snaplen = 80
        px.set_promiscuous(True)
        px.set_timeout(0)
        px.set_immediate_mode(True)
        px.set_buffer_size(4096) 
        try:
            px.set_tstamp_type(PcapTstampType.Host)
        except:
            pass
        self.assertEqual(px.tstamp_precision, pf.PcapTstampPrecision.Micro)
        xlist = px.list_tstamp_types()
        self.assertIsInstance(xlist, list)
        try:
            px.tstamp_precision = PcapTstampPrecision.Nano
            self.assertEqual(px.tstamp_precision, pf.PcapTstampPrecision.Nano)
        except:
            self.assertEqual(px.tstamp_precision, pf.PcapTstampPrecision.Micro)
        with self.assertRaises(pf.PcapException):
            px.blocking
        with self.assertRaises(pf.PcapException):
            px.blocking = True
        with self.assertRaises(pf.PcapException):            
            x = px.dlt # exc because not activated
        self.assertEqual(px.fd, -1)     
        with self.assertRaises(pf.PcapException):
            px.send_packet("hello, world") # not bytes
        self.assertIsNone(px.recv_packet(0))
        self.assertIsNone(px.recv_packet_or_none())
        with self.assertRaises(pf.PcapException):
            px.set_direction(pf.PcapDirection.InOut) # not active
        #with self.assertRaises(pf.PcapException):
        #    px.set_filter("icmp") # not active
        px.close()

if __name__ == '__main__':
    unittest.main(verbosity=1)
