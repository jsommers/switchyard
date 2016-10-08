import sys
import argparse
import os
import signal
import re
import subprocess
import time
import threading
import textwrap
from queue import Queue,Empty
from socket import gethostname

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.pcapffi import *
from switchyard.lib.importcode import import_or_die

_dlt_to_decoder = {}
_dlt_to_decoder[Dlt.DLT_EN10MB] = lambda raw: Packet(raw, first_header=Ethernet)
_dlt_to_decoder[Dlt.DLT_NULL] = lambda raw: Packet(raw, first_header=Null)

'''
Low-level-ish packet library for PyRouter project.  Uses a FFI-based
pcap bridge library (pcapffi) for receiving and sending packets, 
and the Switchyard packet library for packet parsing.

jsommers@colgate.edu
'''

USERMAIN = 'switchy_main'

from switchyard.lib.common import Interface, SwitchyException, Shutdown, NoPackets, LLNetBase
from switchyard.lib.common import setup_logging, log_info, log_debug, log_warn, log_failure
from switchyard.lib.textcolor import *


class PyLLNet(LLNetBase):
    '''
    A class that represents a collection of network devices
    on which packets can be received and sent.
    '''

    def __init__(self, devlist, name=None):
        LLNetBase.__init__(self)
        signal.signal(signal.SIGINT, self._sig_handler)
        signal.signal(signal.SIGTERM, self._sig_handler)
        signal.signal(signal.SIGHUP, self._sig_handler)
        signal.signal(signal.SIGUSR1, self._sig_handler)
        signal.signal(signal.SIGUSR2, self._sig_handler)

        self.devs = devlist # self.__initialize_devices(includelist, excludelist)
        self.devinfo = self.__assemble_devinfo()
        self.pcaps = {}
        self.__make_pcaps()
        log_info("Using network devices: {}".format(' '.join(self.devs)))
        for devname, intf in self.devinfo.items():
            log_debug("{}: {}".format(devname, str(intf)))

        PyLLNet.running = True
        self.__spawn_threads()

        if name:
            self.__name = name
        else:
            self.__name = gethostname()

    @property
    def name(self):
        return self.__name

    def __initialize_devices(self, includes, excludes):
        devs = self.__get_net_devs()
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
        Should be called by Switchyard user code when a network object is
        being shut down.  (This method cleans up internal threads and network
        interaction objects.)
        '''
        if not PyLLNet.running:
            return

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

    def __assemble_devinfo(self):
        '''
        Internal method.  Assemble information on each interface/
        device that we know about, i.e., its MAC address and configured
        IP address and prefix.
        '''
        devinfo = {}

        # beautiful/ugly regular expressions
        hwaddr = re.compile("HWaddr ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})")
        ether = re.compile("ether ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})")
        ipmasklinux = re.compile("inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+Bcast:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+Mask:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        ipmaskosx = re.compile("inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+netmask (0x[0-9a-f]{8})")
        # FIXME: ip6

        ifnum = 0
        for devname in self.devs:
            macaddr = None
            ipaddr = None
            mask = None
            output = subprocess.check_output(["ifconfig", devname])
            for line in output.decode('ascii','').split('\n'):
                mobj = hwaddr.search(line)
                if mobj:
                    macaddr = EthAddr(mobj.groups()[0])
                else:
                    mobj = ether.search(line)
                    if mobj:
                        macaddr = EthAddr(mobj.groups()[0])
                mobj = ipmasklinux.search(line)
                if mobj:
                    ipaddr = IPAddr(mobj.groups()[0])
                    mask = IPAddr(mobj.groups()[2])
                else:
                    mobj = ipmaskosx.search(line)
                    if mobj:
                        ipaddr = IPAddr(mobj.groups()[0])
                        mask = IPAddr(int(mobj.groups()[1], base=16))
            devinfo[devname] = Interface(devname, macaddr, ipaddr, mask, ifnum)
            ifnum += 1
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
            pdev = PcapLiveDevice(dev) # default snaplen is 64k
            # pcap FIXME
            # pdev.setfilter("not ether src {}".format(thismac))
            self.pcaps[dev] = pdev

    def _sig_handler(self, signum, stack):
        '''
        Handle process INT signal.
        '''
        log_debug("Got SIGINT.")
        if signum == signal.SIGINT:
            PyLLNet.running = False
            if self.pktqueue.qsize() == 0:
                # put dummy pkt in queue to unblock a 
                # possibly stuck user thread
                self.pktqueue.put( (None,None,None) )
            self.pktqueue = Queue()

    @staticmethod
    def __low_level_dispatch(pcapdev, devname, pktqueue):
        '''
        Thread entrypoint for doing low-level receive and dispatch
        for a single pcap device.
        '''
        count = 0
        while PyLLNet.running:
            # a non-zero timeout value is ok here; this is an
            # independent thread that handles input for this
            # one pcap device.  it throws any packets received
            # into the shared queue (which is read by the actual
            # user code)
            pktinfo = pcapdev.recv_packet(timeout=0.2)
            if pktinfo is None:
                continue
            log_debug("Got packet on device {}, dlt {}".format(devname, pcapdev.dlt))
            pktqueue.put( (devname,pcapdev.dlt,pktinfo) )
            count += 1
            if count % 100 == 0:
                stats = pcapdev.stats()
                log_debug("Periodic device statistics {}: {} received, {} dropped, {} dropped/if".format(devname, stats.ps_recv, stats.ps_drop, stats.ps_ifdrop))

        log_debug("Receiver thread for {} exiting".format(devname))
        stats = pcapdev.stats()
        log_debug("Final device statistics {}: {} received, {} dropped, {} dropped/if".format(devname, stats.ps_recv, stats.ps_drop, stats.ps_ifdrop))

    def recv_packet(self, timeout=None, timestamp=False):
        '''
        Receive packets from any device on which one is available.
        Blocks until it receives a packet, unless a timeout value >=0
        is given.  Raises Shutdown exception when device(s) are shut 
        down (i.e., on a SIGINT to the process).  Raises NoPackets when 
        there are no packets that can be read.

        Returns a tuple of length 2 or 3, depending on whether the
        timestamp is desired.

         * device: network device name on which packet was received
           as a string
         * timestamp: floating point value of time at which packet
           was received (optionally returned; only if
           timestamp=True)
         * packet: Switchyard Packet object.
        '''
        while True:
            try:
                dev,dlt,pktinfo = self.pktqueue.get(timeout=timeout)
                if not PyLLNet.running:
                    break

                decoder = _dlt_to_decoder.get(dlt, None)
                if decoder is None:
                    log_warn("Received packet with unparseable encapsulation {}".format(dlt))
                    continue

                pkt = decoder(pktinfo.raw) 
                if timestamp:
                    return dev,pktinfo.timestamp,pkt
                else:
                    return dev,pkt
            except Empty:
                raise NoPackets()
        raise Shutdown()

    def send_packet(self, dev, packet):
        '''
        Send a Switchyard Packet object on the given device 
        (string name of device).

        Raises SwitchyException if packet object isn't valid, or device
        name isn't recognized.
        '''
        if isinstance(dev, int):
           dev = self._lookup_devname(dev)

        if isinstance(dev, Interface):
           dev = dev.name

        pdev = self.pcaps.get(dev, None)
        if not pdev:
            raise SwitchyException("Unrecognized device name for packet send: {}".format(dev))
        else:
            if packet is None:
                raise SwitchyException("No packet object given to send_packet")
            if not isinstance(packet, Packet):
                raise SwitchyException("Object given to send_packet is not a Packet (it is: {})".format(type(packet)))
            # convert packet to bytes and send it
            rawpkt = packet.to_bytes()
            log_debug("Sending packet on device {}: {}".format(dev, str(packet)))
            pdev.send_packet(rawpkt)

def main_real(usercode, netobj, options):
    '''
    Entrypoint function for non-test ("real") mode.  At this point
    we assume that we are running as root and have pcap module.
    '''
    usercode_entry_point = import_or_die(usercode, ('main','srpy_main','switchy_main'))
    if options.dryrun:
        log_info("Imported your code successfully.  Exiting dry run.")
        netobj.shutdown()
        return

    try:
        usercode_entry_point(netobj)
    except Exception as e:
        import traceback

        log_failure("Exception while running your code: {}".format(e))
        message = '''{0}

This is the Switchyard equivalent of the blue screen of death.
Here (repeating what's above) is the failure that occurred:
'''.format('*'*60, textwrap.fill(str(e), 60))
        with red():
            print(message)
            traceback.print_exc(1)
            print('*'*60)

        if options.nohandle:
            raise 
            
        if not options.nopdb:
            print('''
I'm throwing you into the Python debugger (pdb) at the point of failure.
If you don't want pdb, use the --nopdb flag to avoid this fate.
''')
            import pdb
            pdb.post_mortem()
    else:
        netobj.shutdown()
