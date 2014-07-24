from __future__ import print_function
import sys
from cffi import FFI
from collections import namedtuple
from enum import Enum
from time import time,sleep
from select import select

Interface = namedtuple('Interface', ['name','isloop'])
PcapStats = namedtuple('PcapStats', ['ps_recv','ps_drop','ps_ifdrop'])
Packet = namedtuple('Packet', ['timestamp', 'capture_length', 'length', 'packet'])
PcapDev = namedtuple('PcapDev', ['dlt','nonblock','snaplen','version','pcap'])

class PcapException(Exception):
    pass

class Dlt(Enum):
    '''
    Data link type enumeration.  Mirrors basic
    dlts in libpcap.
    '''
    DLT_NULL        = 0 
    DLT_EN10MB      = 1 
    DLT_EN3MB       = 2 
    DLT_AX25        = 3
    DLT_PRONET      = 4
    DLT_CHAOS       = 5
    DLT_IEEE802     = 6
    DLT_ARCNET      = 7
    DLT_SLIP        = 8
    DLT_PPP         = 9
    DLT_FDDI        = 10
    DLT_LINUX_SLL   = 113

class _PcapFfi(object):
    '''
    This class represents the low-level interface to the libpcap library.
    It encapsulates all the cffi calls and C/Python conversions, as well
    as translation of errors and error codes to PcapExceptions.  It is
    intended to be used as a singleton class through the PcapDumper
    and PcapLiveDevice classes, below.
    '''
    __instance = None
    __slots__ = ['__ffi', '__libpcap','__interfaces']

    def __init__(self):
        if _PcapFfi.__instance:
            raise Exception("Can't initialize this class more than once!")

        _PcapFfi.__instance = self

        self.__ffi = FFI()
        self.__ffi.cdef('''
        struct pcap;
        typedef struct pcap pcap_t;
        struct pcap_dumper;
        typedef struct pcap_dumper pcap_dumper_t;
        struct pcap_addr {
            struct pcap_addr *next;
            struct sockaddr *addr;
            struct sockaddr *netmask;
            struct sockaddr *broadaddr;
            struct sockaddr *dstaddr;
        };
        typedef struct pcap_addr pcap_addr_t;
        struct pcap_if {
            struct pcap_if *next;
            char *name;
            char *description;
            pcap_addr_t *addresses;
            int flags;
        };
        typedef struct pcap_if pcap_if_t;

        int pcap_findalldevs(pcap_if_t **, char *);
        void pcap_freealldevs(pcap_if_t *);

        struct pcap_pkthdr {
            unsigned long tv_sec;
            unsigned long tv_usec;
            unsigned int caplen;
            unsigned int len;
        };

        struct pcap_stat {
            unsigned int recv;
            unsigned int drop;
            unsigned int ifdrop;
        };

        pcap_t *pcap_open_dead(int, int);
        pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
        void pcap_dump_close(pcap_dumper_t *);
        void pcap_dump(pcap_dumper_t *, struct pcap_pkthdr *, unsigned char *);

        // live capture
        pcap_t *pcap_create(const char *, char *); // source, errbuf
        pcap_t *pcap_open_live(const char *, int, int, int, char *);
        int pcap_set_snaplen(pcap_t *, int); // 0 on success
        int pcap_snapshot(pcap_t *);
        int pcap_set_promisc(pcap_t *, int); // 0 on success
        int pcap_set_buffer_size(pcap_t *, int); // 0 on success
        int pcap_datalink(pcap_t *);
        int pcap_setnonblock(pcap_t *, int, char *); // 0 on success
        int pcap_getnonblock(pcap_t *, char *); 
        int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
        int pcap_activate(pcap_t *);
        void pcap_close(pcap_t *);
        int pcap_get_selectable_fd(pcap_t *);
        int pcap_sendpacket(pcap_t *, const unsigned char *, int);
        char *pcap_geterr(pcap_t *);
        char *pcap_lib_version();
        int pcap_stats(pcap_t *, struct pcap_stat *);
        ''')
        if sys.platform == 'darwin':
            self.__libpcap = self.__ffi.dlopen('libpcap.dylib')
        else:
            raise PcapException("Don't know how to locate libpcap on this platform: {}".format(sys.platform))
        self.__interfaces = []
        self.discoverdevs()
        # print (self.devices)

    @staticmethod
    def instance():
        if not _PcapFfi.__instance:
            _PcapFfi.__instance = _PcapFfi()
        return _PcapFfi.__instance

    @property
    def version(self):
        return self.__ffi.string(self.__libpcap.pcap_lib_version())

    def discoverdevs(self):
        '''
        Find all the pcap-eligible devices on the local system.
        '''
        ppintf = self.__ffi.new("pcap_if_t * *")
        errbuf = self.__ffi.new("char []", 128)
        rv = self.__libpcap.pcap_findalldevs(ppintf, errbuf)
        if rv:
            raise PcapException("pcap_findalldevs returned failure: {}".format(self.__ffi.string(errbuf)))
        pintf = ppintf[0]
        tmp = pintf
        while tmp != self.__ffi.NULL:
            xname = self.__ffi.string(tmp.name)
            isloop = tmp.flags == 1
            xif = Interface(xname, isloop)
            self.__interfaces.append(xif)
            tmp = tmp.next
        self.__libpcap.pcap_freealldevs(pintf)

    @property
    def devices(self):
        return self.__interfaces

    def open_dumper(self, outfile, dltype=Dlt.DLT_EN10MB, snaplen=65535):
        pcap = self.__libpcap.pcap_open_dead(dltype.value, snaplen)
        xoutfile = self.__ffi.new("char []", bytes(outfile, 'ascii'))
        pcapdump = self.__libpcap.pcap_dump_open(pcap, xoutfile) 
        dl = self.__libpcap.pcap_datalink(pcap)
        snaplen = self.__libpcap.pcap_snapshot(pcap)
        return PcapDev(Dlt(dl), 0, snaplen, self.version, pcapdump)

    def close_dumper(self, pcapdump):
        self.__libpcap.pcap_dump_close(pcapdump)

    def write_packet(self, dumper, pkt, ts=None):
        pkthdr = self.__ffi.new("struct pcap_pkthdr *")
        if not ts:
            ts = time()
        pkthdr.tv_sec = int(ts)
        pkthdr.tv_usec = int(1000000*(ts-int(ts)))
        pkthdr.caplen = len(pkt)
        pkthdr.len = len(pkt)
        xpkt = self.__ffi.new("char []", pkt)
        self.__libpcap.pcap_dump(dumper, pkthdr, xpkt)

    def open_live(self, device, snaplen=65535, promisc=1, to_ms=100, nonblock=True):
        errbuf = self.__ffi.new("char []", 128)
        pcap = self.__libpcap.pcap_open_live(bytes(device, 'ascii'), snaplen, promisc, to_ms, errbuf)
        if pcap == self.__ffi.NULL:
            raise PcapException("Failed to open live device {}: {}".format(device, self.__ffi.string(errbuf)))

        if nonblock:
            rv = self.__libpcap.pcap_setnonblock(pcap, 1, errbuf)
            if rv != 0:
                raise PcapException("Error setting pcap device in nonblocking state: {}".format(self.__ffi.string(errbuf)))

        # gather what happened
        nblock = self.__libpcap.pcap_getnonblock(pcap, errbuf)
        dl = self.__libpcap.pcap_datalink(pcap)
        snaplen = self.__libpcap.pcap_snapshot(pcap)
        return PcapDev(Dlt(dl), nblock, snaplen, self.version, pcap)

    def close_live(self, pcap):
        self.__libpcap.pcap_close(pcap)

    def get_select_fd(self, xpcap):
        return self.__libpcap.pcap_get_selectable_fd(xpcap)

    def send_packet(self, xpcap, xbuffer):
        if not isinstance(xbuffer, bytes):
            raise PcapException("Packets to be sent via libpcap must be serialized as a bytes object")
        xlen = len(xbuffer)
        rv = self.__libpcap.pcap_sendpacket(xpcap, xbuffer, xlen)
        if rv == 0:
            return True
        s = self.__ffi.string(self.__libpcap.pcap_geterr(xpcap))
        raise PcapException("Error sending packet: {}".format(s))

    def recv_packet(self, xpcap):
        phdr = self.__ffi.new("struct pcap_pkthdr **")
        pdata = self.__ffi.new("unsigned char **")
        rv = self.__libpcap.pcap_next_ex(xpcap, phdr, pdata)
        if rv == 1:
            rawpkt = bytes(self.__ffi.buffer(pdata[0], phdr[0].caplen))
            ts = float("{}.{}".format(phdr[0].tv_sec, phdr[0].tv_usec))
            return Packet(ts, phdr[0].caplen, phdr[0].len, rawpkt)
        elif rv == 0:
            # timeout; nothing to return
            return None
        elif rv == -1:
            # error on receive; raise an exception
            s = self.__ffi.string(self.__libpcap.pcap_geterr(xpcap))
            raise PcapException("Error receiving packet: {}".format(s)) 
        elif rv == -2:
            # reading from savefile, but none left
            return None

    def stats(self, xpcap):
        pstat = self.__ffi.new("struct pcap_stat *")
        rv = self.__libpcap.pcap_stats(xpcap, pstat)
        if rv == 0:
            return PcapStats(pstat.recv,pstat.drop,pstat.ifdrop)
        else:
            s = self.__ffi.string(self.__libpcap.pcap_geterr(xpcap))
            raise PcapException("Error getting stats: {}".format(s))

class PcapDumper(object):
    __slots__ = ['__pcapffi','__dumper']
    def __init__(self, outfile):
        self.__pcapffi = _PcapFfi.instance()
        self.__dumper = self.__pcapffi.open_dumper(outfile)
        print ("Got pcap dump device: {}".format(self.__dumper))

    def write_packet(self, pkt, ts=None):
        if not isinstance(pkt, bytes):
            raise PcapException("Packet to be written needs to be a Python bytes object")
        self.__pcapffi.write_packet(self.__dumper.pcap, pkt, ts=ts)

    def close(self):
        self.__pcapffi.close_dumper(self.__dumper.pcap)

class PcapLiveDevice(object):
    '''
    Class the represents a live pcap capture/injection device.
    '''
    __slots__ = ['__pcapffi','__pcapdev']

    def __init__(self, device, snaplen=65535, promisc=1, to_ms=100):
        self.__pcapffi = _PcapFfi.instance()
        self.__pcapdev = self.__pcapffi.open_live(device)
        print ("Got live pcap device: {}".format(self.__pcapdev))

    def recv_packet(self, timeout):
        if timeout < 0:
            timeout = None
        fd = self.__pcapffi.get_select_fd(self.__pcapdev.pcap)
        if fd >= 0:
            xread,xwrite,xerr = select([fd], [], [fd], timeout)
            if xread:  
                return self.__pcapffi.recv_packet(self.__pcapdev.pcap)
            # timeout; return nothing
            return None
        elif self.__pcapdev.nonblock:
            # can't do select, but we're in nonblocking mode so sleep
            # up to 10 times before giving up, all while respecting the
            # timeout value
            if timeout:
                now = time()
                expiry = now + timeout
                while now < expiry:
                    sleep(timeout/10)
                    pkt = self.__pcapffi.recv_packet(self.pcapdev.pcap)
                    if pkt:
                        return pkt
                    now = time()
                # after all that, still got nothing.
                return None
            else:
                return self.__pcapffi.recv_packet(self.__pcapdev.pcap)
        else:
            # no select, no non-blocking mode.  block away, my friend.
            return self.__pcapffi.recv_packet(self.__pcapdev.pcap)

    def send_packet(self, packet):
        self.__pcapffi.send_packet(self.__pcapdev.pcap, packet)

    def close(self):
        self.__pcapffi.close_live(self.__pcapdev.pcap)

    def stats(self):
        return self.__pcapffi.stats(self.__pcapdev.pcap)

_PcapFfi()


if __name__ == '__main__':
    dump = PcapDumper("outfile.pcap")
    pkt = b'\xff\xff\xff\xff\xff\xff\x68\xa8\x6d\x04\xbd\x86\x08\x00' + b'\x00'*20
    dump.write_packet(pkt)

    p = PcapLiveDevice('en0')
    # p.send_packet(pkt)
    # p.close()

    for _ in range(2):
        rv = p.recv_packet(5.0)
        if rv:
            print (rv)
            dump.write_packet(rv.packet)
    print ("Stats: {}".format(p.stats()))
    p.close()

    dump.close()
