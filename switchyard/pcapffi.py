from __future__ import print_function
import sys
from cffi import FFI
from collections import namedtuple
from enum import Enum
from time import time,sleep
from select import select
from threading import Lock

PcapInterface = namedtuple('PcapInterface', ['name','internal_name', 'description', 'isloop','isup','isrunning'])
PcapStats = namedtuple('PcapStats', ['ps_recv','ps_drop','ps_ifdrop'])
PcapPacket = namedtuple('PcapPacket', ['timestamp', 'capture_length', 'length', 'raw'])
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
    DLT_RAW         = 12
    DLT_LINUX_SLL   = 113

class _PcapFfi(object):
    '''
    This class represents the low-level interface to the libpcap library.
    It encapsulates all the cffi calls and C/Python conversions, as well
    as translation of errors and error codes to PcapExceptions.  It is
    intended to be used as a singleton class through the PcapDumper
    and PcapLiveDevice classes, below.
    '''
    _instance = None
    __slots__ = ['_ffi', '_libpcap','_interfaces','_windoze']

    def __init__(self):
        '''
        Assumption: this class is instantiated once in the main thread before
        any other threads have a chance to try instantiating it.
        '''
        if _PcapFfi._instance:
            raise Exception("Can't initialize this class more than once!")

        _PcapFfi._instance = self
        self._windoze = False

        self._ffi = FFI()
        self._ffi.cdef('''
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
        pcap_t *pcap_open_offline(const char *fname, char *errbuf);
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

        struct bpf_insn;
        struct bpf_program {
            unsigned int bf_len;
            struct bpf_insn *bf_insns;
        };
        int pcap_setfilter(pcap_t *, struct bpf_program *);
        int pcap_compile(pcap_t *, struct bpf_program *,
            const char *, int, unsigned int);
        void pcap_freecode(struct bpf_program *);
        ''')
        if sys.platform == 'darwin':
            self._libpcap = self._ffi.dlopen('libpcap.dylib') # standard libpcap
        elif sys.platform == 'linux':
            self._libpcap = self._ffi.dlopen('libpcap.so') # standard libpcap
        elif sys.platform == 'win32':
            self._libpcap = self._ffi.dlopen('wpcap.dll') # winpcap
            self._windoze = True
        else:
            raise PcapException("Don't know how to locate libpcap on this platform: {}".format(sys.platform))
        self._interfaces = []
        self.discoverdevs()

    @staticmethod
    def instance():
        if not _PcapFfi._instance:
            _PcapFfi._instance = _PcapFfi()
        return _PcapFfi._instance

    @property
    def version(self):
        return self._ffi.string(self._libpcap.pcap_lib_version())

    def discoverdevs(self):
        '''
        Find all the pcap-eligible devices on the local system.
        '''
        if len(self._interfaces):
            raise PcapException("Device discovery should only be done once.")
            
        ppintf = self._ffi.new("pcap_if_t * *")
        errbuf = self._ffi.new("char []", 128)
        rv = self._libpcap.pcap_findalldevs(ppintf, errbuf)
        if rv:
            raise PcapException("pcap_findalldevs returned failure: {}".format(self._ffi.string(errbuf)))
        pintf = ppintf[0]
        tmp = pintf
        pindex = 0
        while tmp != self._ffi.NULL:
            xname = self._ffi.string(tmp.name) # "internal name"; still stored as bytes object
            xname = xname.decode('ascii', 'ignore')

            if self._windoze:
                ext_name = "port{}".format(pindex)
            else:
                ext_name = xname
            pindex += 1

            if tmp.description == self._ffi.NULL:
                xdesc = ext_name
            else:
                xdesc = self._ffi.string(tmp.description)
                xdesc = xdesc.decode('ascii', 'ignore')

            # NB: on WinPcap, only loop flag is set
            isloop = (tmp.flags & 0x1) == 0x1
            isup = (tmp.flags & 0x2) == 0x2
            isrunning = (tmp.flags & 0x4) == 0x4

            xif = PcapInterface(ext_name, xname, xdesc, isloop, isup, isrunning)

            self._interfaces.append(xif)
            tmp = tmp.next
        self._libpcap.pcap_freealldevs(pintf)

    @property 
    def devices(self):
        return self._interfaces

    def open_dumper(self, outfile, dltype=Dlt.DLT_EN10MB, snaplen=65535):
        pcap = self._libpcap.pcap_open_dead(dltype.value, snaplen)
        xoutfile = self._ffi.new("char []", bytes(outfile, 'ascii'))
        pcapdump = self._libpcap.pcap_dump_open(pcap, xoutfile) 
        dl = self._libpcap.pcap_datalink(pcap)
        snaplen = self._libpcap.pcap_snapshot(pcap)
        return PcapDev(Dlt(dl), 0, snaplen, self.version, pcapdump)

    def close_dumper(self, pcapdump):
        self._libpcap.pcap_dump_close(pcapdump)

    def write_packet(self, dumper, pkt, ts=None):
        pkthdr = self._ffi.new("struct pcap_pkthdr *")
        if not ts:
            ts = time()
        pkthdr.tv_sec = int(ts)
        pkthdr.tv_usec = int(1000000*(ts-int(ts)))
        pkthdr.caplen = len(pkt)
        pkthdr.len = len(pkt)
        xpkt = self._ffi.new("unsigned char []", pkt)
        self._libpcap.pcap_dump(dumper, pkthdr, xpkt)

    def open_pcap_file(self, filename):
        errbuf = self._ffi.new("char []", 128)
        pcap = self._libpcap.pcap_open_offline(bytes(filename, 'ascii'), errbuf)
        if pcap == self._ffi.NULL:
            raise PcapException("Failed to open pcap file for reading: {}: {}".format(filename, self._ffi.string(errbuf)))
        
        dl = self._libpcap.pcap_datalink(pcap)
        try:
            dl = Dlt(dl)
        except ValueError as e:
            raise PcapException("Don't know how to handle datalink type {}".format(dl))
        return PcapDev(dl, 0, 0, self.version, pcap)

    def open_live(self, device, snaplen=65535, promisc=1, to_ms=100, nonblock=True):
        errbuf = self._ffi.new("char []", 128)
        internal_name = None
        for dev in self._interfaces:
            if dev.name == device:
                internal_name = dev.internal_name
                break
        if internal_name is None:
            raise Exception("No such device {} exists.".format(device))

        pcap = self._libpcap.pcap_open_live(bytes(internal_name, 'ascii'), snaplen, promisc, to_ms, errbuf)
        if pcap == self._ffi.NULL:
            raise PcapException("Failed to open live device {}: {}".format(internal_name, self._ffi.string(errbuf)))

        if nonblock:
            rv = self._libpcap.pcap_setnonblock(pcap, 1, errbuf)
            if rv != 0:
                raise PcapException("Error setting pcap device in nonblocking state: {}".format(self._ffi.string(errbuf)))

        # gather what happened
        nblock = self._libpcap.pcap_getnonblock(pcap, errbuf)
        snaplen = self._libpcap.pcap_snapshot(pcap)
        dl = self._libpcap.pcap_datalink(pcap)
        try:
            dl = Dlt(dl)
        except ValueError as e:
            raise PcapException("Don't know how to handle datalink type {}".format(dl))
        return PcapDev(dl, nblock, snaplen, self.version, pcap)

    def close_live(self, pcap):
        self._libpcap.pcap_close(pcap)

    def get_select_fd(self, xpcap):
        try:
            return self._libpcap.pcap_get_selectable_fd(xpcap)
        except:
            return -1

    def send_packet(self, xpcap, xbuffer):
        if not isinstance(xbuffer, bytes):
            raise PcapException("Packets to be sent via libpcap must be serialized as a bytes object")
        xlen = len(xbuffer)
        rv = self._libpcap.pcap_sendpacket(xpcap, xbuffer, xlen)
        if rv == 0:
            return True
        s = self._ffi.string(self._libpcap.pcap_geterr(xpcap))
        raise PcapException("Error sending packet: {}".format(s))

    def recv_packet(self, xpcap):
        phdr = self._ffi.new("struct pcap_pkthdr **")
        pdata = self._ffi.new("unsigned char **")
        rv = self._libpcap.pcap_next_ex(xpcap, phdr, pdata)
        if rv == 1:
            rawpkt = bytes(self._ffi.buffer(pdata[0], phdr[0].caplen))
            ts = float("{}.{}".format(phdr[0].tv_sec, phdr[0].tv_usec))
            return PcapPacket(ts, phdr[0].caplen, phdr[0].len, rawpkt)
        elif rv == 0:
            # timeout; nothing to return
            return None
        elif rv == -1:
            # error on receive; raise an exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xpcap))
            raise PcapException("Error receiving packet: {}".format(s)) 
        elif rv == -2:
            # reading from savefile, but none left
            return None

    def set_filter(self, xpcap, filterstr):
        bpf = self._ffi.new("struct bpf_program *")
        cfilter = self._ffi.new("char []", bytes(filterstr, 'ascii'))
        compile_result = self._libpcap.pcap_compile(xpcap.pcap, bpf, cfilter, 0, 0xffffffff)
        if compile_result < 0:
            # get error, raise exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xpcap.pcap))
            raise PcapException("Error compiling filter expression: {}".format(s)) 

        sf_result = self._libpcap.pcap_setfilter(xpcap.pcap, bpf)
        if sf_result < 0:
            # get error, raise exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xpcap.pcap))
            raise PcapException("Error setting filter on pcap handle: {}".format(s)) 
        self._libpcap.pcap_freecode(bpf)

    def stats(self, xpcap):
        pstat = self._ffi.new("struct pcap_stat *")
        rv = self._libpcap.pcap_stats(xpcap, pstat)
        if rv == 0:
            return PcapStats(pstat.recv,pstat.drop,pstat.ifdrop)
        else:
            s = self._ffi.string(self._libpcap.pcap_geterr(xpcap))
            raise PcapException("Error getting stats: {}".format(s))

def pcap_devices():
    return _PcapFfi.instance().devices

class PcapDumper(object):
    __slots__ = ['_pcapffi','_dumper']
    def __init__(self, outfile):
        self._pcapffi = _PcapFfi.instance()
        self._dumper = self._pcapffi.open_dumper(outfile)
        # print ("Got pcap dump device: {}".format(self._dumper))

    def write_packet(self, pkt, ts=None):
        if not isinstance(pkt, bytes):
            raise PcapException("Packet to be written needs to be a Python bytes object")
        self._pcapffi.write_packet(self._dumper.pcap, pkt, ts=ts)

    def close(self):
        self._pcapffi.close_dumper(self._dumper.pcap)

class PcapReader(object):
    '''
    Class the represents a reader of an existing pcap capture file.
    '''
    __slots__ = ['_pcapffi','_pcapdev']

    def __init__(self, filename, filterstr=None):
        self._pcapffi = _PcapFfi.instance()
        self._pcapdev = self._pcapffi.open_pcap_file(filename)
        if filterstr is not None:
            self._pcapffi.set_filter(self._pcapdev, filterstr)

    def close(self):
        self._pcapffi.close_live(self._pcapdev.pcap)

    def recv_packet(self):
        return self._pcapffi.recv_packet(self._pcapdev.pcap)

class PcapLiveDevice(object):
    '''
    Class the represents a live pcap capture/injection device.
    '''
    _OpenDevices = {}
    _lock = Lock()
    __slots__ = ['_pcapffi','_pcapdev','_devname']

    def __init__(self, device, snaplen=65535, promisc=1, to_ms=100, filterstr=None):
        self._pcapffi = _PcapFfi.instance()
        self._pcapdev = self._pcapffi.open_live(device)
        self._devname = device
        with PcapLiveDevice._lock:
            PcapLiveDevice._OpenDevices[self._devname] = self._pcapdev
        if filterstr is not None:
            self._pcapffi.set_filter(self._pcapdev, filterstr)

    @staticmethod
    def set_bpf_filter_on_all_devices(filterstr):
        '''
        Long method name, but self-explanatory.  Set the bpf
        filter on all devices that have been opened.
        '''
        with PcapLiveDevice._lock:
            for dev in PcapLiveDevice._OpenDevices.values():
                _PcapFfi.instance().set_filter(dev, filterstr)

    @property
    def dlt(self):
        return self._pcapdev.dlt

    def recv_packet(self, timeout):
        if timeout is None or timeout < 0:
            timeout = None

        fd = self._pcapffi.get_select_fd(self._pcapdev.pcap)
        if fd >= 0:
            try:
                xread,xwrite,xerr = select([fd], [], [fd], timeout)
            except:
                return None
            if xread:  
                return self._pcapffi.recv_packet(self._pcapdev.pcap)
            # timeout; return nothing
            return None
        elif self._pcapdev.nonblock:
            # can't do select, but we're in nonblocking mode so sleep
            # up to 10 times before giving up, all while respecting the
            # timeout value
            if timeout:
                now = time()
                expiry = now + timeout
                while now < expiry:
                    sleep(timeout/10)
                    pkt = self._pcapffi.recv_packet(self._pcapdev.pcap)
                    if pkt:
                        return pkt
                    now = time()
                # after all that, still got nothing.
                return None
            else:
                return self._pcapffi.recv_packet(self._pcapdev.pcap)
        else:
            # no select, no non-blocking mode.  block away, my friend.
            return self._pcapffi.recv_packet(self._pcapdev.pcap)

    def send_packet(self, packet):
        self._pcapffi.send_packet(self._pcapdev.pcap, packet)

    def close(self):
        with PcapLiveDevice._lock:
            # print("In close; existing devs: {}".format(list(PcapLiveDevice._OpenDevices.keys())))
            del PcapLiveDevice._OpenDevices[self._devname]
        self._pcapffi.close_live(self._pcapdev.pcap)

    def stats(self):
        return self._pcapffi.stats(self._pcapdev.pcap)

    def set_filter(self, filterstr):
        self._pcapffi.set_filter(self._pcapdev, filterstr)

_PcapFfi() # instantiate singleton

if __name__ == '__main__':
    print ("Found devices: ")
    for dev in pcap_devices():
        print(str(dev))
