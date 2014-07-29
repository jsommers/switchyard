import sys
import argparse
import os
import signal
import re
import subprocess
import time
import threading
from queue import Queue,Empty

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.pcapffi import *
from switchyard.lib.importcode import import_user_code

'''
Low-level-ish packet library for PyRouter project.  Uses libpcap
for receiving and sending packets, and the POX controller utility
libraries for packet parsing.  It is Ethernet and IPv4-centric.

jsommers@colgate.edu
'''

USERMAIN = 'switchy_main'

from switchyard.lib.common import Interface, SwitchyException, Shutdown, NoPackets, ScenarioFailure, PacketFormatter, LLNetBase
from switchyard.lib.common import setup_logging, log_info, log_debug, log_warn, log_failure
from switchyard.lib.textcolor import *


class PyLLNet(LLNetBase):
    '''
    A class that represents a collection of network devices
    on which packets can be received and sent.
    '''

    def __init__(self, environment, includelist, excludelist):
        LLNetBase.__init__(self)
        signal.signal(signal.SIGINT, PyLLNet.__sig_handler)
        signal.signal(signal.SIGTERM, PyLLNet.__sig_handler)
        signal.signal(signal.SIGHUP, PyLLNet.__sig_handler)
        signal.signal(signal.SIGUSR1, PyLLNet.__sig_handler)
        signal.signal(signal.SIGUSR2, PyLLNet.__sig_handler)

        self.devs = self.__initialize_devices(environment, includelist, excludelist)
        self.devinfo = self.__assemble_devinfo()
        self.pcaps = {}
        self.__make_pcaps()
        log_info("Found network devices: {}".format(' '.join(self.devs)))
        for devname, intf in self.devinfo.items():
            log_debug("{}: {}".format(devname, str(intf)))

        PyLLNet.running = True
        self.__spawn_threads()

    def __initialize_devices(self, env, includes, excludes):
        devs = self.__get_net_devs(env)
        print ("Devs: {}".format(devs))
        if not devs:
            raise SwitchyException("No suitable interfaces found.")

        # remove devs from excludelist
        devs.difference_update(set(excludes))

        # if includelist is non-empty, perform
        # intersection with devs found and includelist
        if includes:
            devs.intersection_update(set(includes))

        if not devs:
            raise SwitchyException("No interfaces enabled after handling include/exclude lists")

        return devs

    def shutdown(self):
        '''
        Should be called by pynet user when a PyLLNet object is
        being shut down.  Cleans up internal threads and network
        interaction objects.
        '''
        PyLLNet.running = False
        log_debug("Joining threads for shutdown")
        for t in self.threads:
            t.join()
        log_debug("Closing pcap devices")
        for devname,pdev in self.pcaps.items():
            pdev.close()
        log_debug("Done cleaning up")

    def __spawn_threads(self):
        '''
        Internal method.  Creates threads to handle low-level
        network receive.
        '''
        self.threads = []
        self.pktqueue = Queue()
        for devname,pdev in self.pcaps.items():
            t = threading.Thread(target=PyLLNet.__low_level_dispatch, args=(pdev, devname, self.pktqueue))
            t.start()
            self.threads.append(t)

    def __get_net_devs(self, environment):
        '''
        Internal method.  Find all "valid" network devices
        on the host.  Assumes naming convention in
        project mininet code.
        '''
        devs = set()
        xlist = open('/proc/net/dev').readlines()
        xlist.pop(0) # ignore header line
        # match standard mininet node naming conventions, e.g.,
        # router0-eth0, s0-eth0, switch-eth0
        if environment == 'mininet':
            pattern = re.compile('^[A-Za-z]+\d*-eth\d+')
        else:
            pattern = re.compile('^eth\d+')

        for line in xlist:
            fields = line.split()
            if pattern.match(fields[0]):
                devs.add(fields[0].strip(':'))
        return devs

    def __assemble_devinfo(self):
        '''
        Internal method.  Assemble information on each interface/
        device that we know about, i.e., its MAC address and configured
        IP address and prefix.
        '''
        devinfo = {}

        # beautiful/ugly regular expressions
        hwaddr = re.compile("HWaddr ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})")
        ipmask = re.compile("inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+Bcast:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+Mask:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        for devname in self.devs:
            macaddr = None
            ipaddr = None
            mask = None
            output = subprocess.check_output(["ifconfig", devname])
            for line in output.split('\n'):
                mobj = hwaddr.search(line)
                if mobj:
                    macaddr = EthAddr(mobj.groups()[0])
                mobj = ipmask.search(line)
                if mobj:
                    ipaddr = IPAddr(mobj.groups()[0])
                    mask = IPAddr(mobj.groups()[2])
            devinfo[devname] = Interface(devname, macaddr, ipaddr, mask)
        return devinfo

    def __make_pcaps(self):
        '''
        Internal method.  Create libpcap devices
        for every network interface we care about and
        set them in non-blocking mode.
        '''
        self.pcaps = {}
        for dev in self.devs:
            thismac = self.devinfo[dev].ethaddr
            pdev = pcap.pcap(name=dev) # default snaplen is 64k
            pdev.setnonblock(1)
            pdev.setfilter("not ether src {}".format(thismac))
            log_debug("Result of setting device {} in non-blocking mode: {}".format(dev, pdev.getnonblock()))
            self.pcaps[dev] = pdev

    @staticmethod
    def __sig_handler(signum, stack):
        '''
        Handle process INT signal.
        '''
        log_debug("Got SIGINT.")
        if signum == signal.SIGINT:
            PyLLNet.running = False

    @staticmethod
    def __low_level_dispatch(pcapdev, devname, pktqueue):
        '''
        Thread entrypoint for doing low-level receive and dispatch
        for a single pcap device.
        '''
        while PyLLNet.running:
            pkts_processed = pcapdev.dispatch(-1, PyLLNet.__low_level_recv, devname, pktqueue)
            if pkts_processed > 0:
                log_debug("Receiver thread {} got {} pkts".format(devname, pkts_processed))
            time.sleep(0.1)

        log_debug("Receiver thread for {} exiting".format(devname))
        nreceived, ndropped, ndroppedif = pcapdev.stats()
        log_debug("Device statistics {}: {} received, {} dropped, {} dropped/if".format(devname, nreceived, ndropped, ndroppedif))

    @staticmethod
    def __low_level_recv(ts, rawpkt, *args):
        '''
        Callback function for pcap dispatch.  Receive packet and
        enqueue it for the main thread to deliver back to user code.
        '''
        devname, pktqueue = args[0],args[1]
        ethpkt = ethernet(raw=bytes(rawpkt))
        log_debug("Got packet on device {}".format(devname))
        pktqueue.put( (devname,ts,ethpkt) )

    def recv_packet(self, timeout=0.0, timestamp=False):
        '''
        Receive packets from any device on which one is available.
        Blocks until it receives a packet.  Returns None,None,None
        when device(s) are shut down (i.e., on a SIGINT to the process).

        Returns a tuple of device,timestamp,packet, where
            device: network device name on which packet was received
                    as a string
            timestamp: floating point value of time at which packet
                    was received
            packet: POX ethernet packet object
        '''
        while PyLLNet.running:
            try:
                rv = self.pktqueue.get(timeout=timeout)
                if timestamp:
                    return rv
                else:
                    return rv[0],rv[2]
            except Empty:
                raise NoPackets()
        raise Shutdown()

    def send_packet(self, dev, packet):
        '''
        Send a POX packet (must be an ethernet packet object) on the
        given device (string name of device).

        Raises an exception if packet object isn't valid, or device
        name isn't recognized.
        '''
        pdev = self.pcaps.get(dev, None)
        if not pdev:
            raise SwitchyException("Unrecognized device name for packet send: {}".format(dev))
        else:
            if packet is None:
                raise SwitchyException("No packet object given to send_packet")
            if not isinstance(packet, ethernet):
                raise SwitchyException("Packet object given to send_packet is not a POX ethernet packet object")
            # convert packet to bytes and send it
            rawpkt = packet.pack()
            log_debug("Sending packet on device {}: {}".format(dev, str(packet)))
            pdev.inject(rawpkt, len(rawpkt))

def main_real(usercode, dryrun, environment, includeintf, excludeintf):
    '''
    Entrypoint function for non-test ("real") mode.  At this point
    we assume that we are running as root and have pcap module.

    (str, bool, str, list(str), list(str)) -> None
    '''
    usercode_entry_point = import_user_code(usercode)
    if dryrun:
        log_info("Imported your code successfully.  Exiting dry run.")
        return
    net = PyLLNet(environment, includeintf, excludeintf)
    try:
        usercode_entry_point(net)
    except Exception as e:
        log_failure("Exception while running your code: {}".format(e))
        net.shutdown()

