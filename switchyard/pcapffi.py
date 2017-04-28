from __future__ import print_function
import sys
from cffi import FFI
from collections import namedtuple
from enum import Enum,IntEnum
from time import time,sleep
from datetime import datetime
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


class PcapDirection(IntEnum):
    InOut = 0
    In = 1
    Out = 2


class PcapTstampType(IntEnum):
    Host = 0
    HostLowPrec = 1
    HostHighPrec = 2
    Adapter = 3
    AdapterUnsync = 4


class PcapTstampPrecision(IntEnum):
    Micro = 0
    Nano = 1


class PcapWarning(IntEnum):
    Generic = 1
    PromiscNotSupported = 2
    TstampTypeNotSupported = 3


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
            long tv_sec;
            long tv_usec;
            unsigned int caplen;
            unsigned int len;
        };

        struct pcap_stat {
            unsigned int recv;
            unsigned int drop;
            unsigned int ifdrop;
        };

        typedef void (*pcap_handler)(unsigned char *, 
                                     const struct pcap_pkthdr *,
                                     const unsigned char *);

        pcap_t *pcap_open_dead(int, int);
        pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
        void pcap_dump_close(pcap_dumper_t *);
        void pcap_dump(pcap_dumper_t *, struct pcap_pkthdr *, unsigned char *);

        // live capture
        pcap_t *pcap_create(const char *, char *); 
        pcap_t *pcap_open_live(const char *, int, int, int, char *);
        pcap_t *pcap_open_offline(const char *fname, char *errbuf);
        int pcap_set_snaplen(pcap_t *, int);
        int pcap_snapshot(pcap_t *);
        int pcap_set_promisc(pcap_t *, int);

        int pcap_set_timeout(pcap_t *, int);
        int pcap_set_buffer_size(pcap_t *, int);

        int pcap_set_tstamp_precision(pcap_t *, int);
        int pcap_get_tstamp_precision(pcap_t *);
        int pcap_set_tstamp_type(pcap_t *, int);
        int pcap_list_tstamp_types(pcap_t *, int **);
        void pcap_free_tstamp_types(int *);

        int pcap_setdirection(pcap_t *, int); 
        int pcap_datalink(pcap_t *);
        int pcap_setnonblock(pcap_t *, int, char *); 
        int pcap_getnonblock(pcap_t *, char *); 
        int pcap_set_immediate_mode(pcap_t *, int);
        int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
        int pcap_dispatch(pcap_t *, int, pcap_handler, unsigned char *);
        int pcap_loop(pcap_t *, int, pcap_handler, unsigned char *);
        void pcap_breakloop(pcap_t *);
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
            libname = 'libpcap.dylib'
        elif sys.platform == 'win32':
            libname = 'wpcap.dll' # winpcap
            self._windoze = True
        else:
            # if not macOS (darwin) or windows, assume we're on
            # some unix-based system and try for libpcap.so
            libname = 'libpcap.so'

        try:
            self._libpcap = self._ffi.dlopen(libname)
        except Exception as e:
            raise PcapException("Error opening libpcap: {}".format(e))

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

            # JS: I've observed that the isup and isrunning flags
            # are patently false on some systems.  As a result, we
            # blindly include all interfaces, regardless of their
            # reported status (though we still include status flags
            # in the interface object).
            # if isup and isrunning:
            xif = PcapInterface(ext_name, xname, xdesc, isloop, isup, isrunning)
            self._interfaces.append(xif)

            tmp = tmp.next
        self._libpcap.pcap_freealldevs(pintf)

    @property 
    def devices(self):
        return self._interfaces

    @property
    def lib(self):
        return self._libpcap

    @property
    def ffi(self):
        return self._ffi

    def _recv_packet(self, xdev):
        phdr = self._ffi.new("struct pcap_pkthdr **")
        pdata = self._ffi.new("unsigned char **")
        rv = self._libpcap.pcap_next_ex(xdev, phdr, pdata)
        if rv == 1:
            rawpkt = bytes(self._ffi.buffer(pdata[0], phdr[0].caplen))
            #dt = datetime.fromtimestamp(phdr[0].tv_sec)
            usec = int(xffi.cast("int", phdr[0].tv_usec))
            #ts = dt.replace(microsecond=usec)
            ts = float("{:d}.{:06d}".format(phdr[0].tv_sec, usec))
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

    def _set_filter(self, xdev, filterstr):
        bpf = self._ffi.new("struct bpf_program *")
        cfilter = self._ffi.new("char []", bytes(filterstr, 'ascii'))
        compile_result = self._libpcap.pcap_compile(xdev, bpf, cfilter, 0, 0xffffffff)
        if compile_result < 0:
            # get error, raise exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xdev))
            raise PcapException("Error compiling filter expression: {}".format(s)) 

        sf_result = self._libpcap.pcap_setfilter(xdev, bpf)
        if sf_result < 0:
            # get error, raise exception
            s = self._ffi.string(self._libpcap.pcap_geterr(xdev))
            raise PcapException("Error setting filter on pcap handle: {}".format(s)) 
        self._libpcap.pcap_freecode(bpf)


def pcap_devices():
    return _PcapFfi.instance().devices


class PcapDumper(object):
    __slots__ = ['_ffi','_libpcap','_base','_dumper']

    def __init__(self, outfile, dltype=Dlt.DLT_EN10MB, snaplen=65535):
        self._base = _PcapFfi.instance()
        self._ffi = self._base.ffi
        self._libpcap = self._base.lib
        pcap = self._libpcap.pcap_open_dead(dltype.value, snaplen)
        xoutfile = self._ffi.new("char []", bytes(outfile, 'ascii'))
        pcapdump = self._libpcap.pcap_dump_open(pcap, xoutfile) 
        dl = self._libpcap.pcap_datalink(pcap)
        snaplen = self._libpcap.pcap_snapshot(pcap)
        self._dumper = PcapDev(Dlt(dl), 0, snaplen, _PcapFfi.instance().version, pcapdump)

    def write_packet(self, pkt, ts=None):
        if not isinstance(pkt, bytes):
            raise PcapException("Packet to be written needs to be a Python bytes object")
        pkthdr = self._ffi.new("struct pcap_pkthdr *")
        if not ts:
            ts = time()

        pkthdr.tv_sec = int(ts)
        pkthdr.tv_usec = int(1000000*(ts-int(ts)))

        pkthdr.caplen = len(pkt)
        pkthdr.len = len(pkt)
        xpkt = self._ffi.new("unsigned char []", pkt)
        self._libpcap.pcap_dump(self._dumper.pcap, pkthdr, xpkt)

    def close(self):
        self._libpcap.pcap_dump_close(self._dumper.pcap)


class PcapReader(object):
    '''
    Class the represents a reader of an existing pcap capture file.
    '''
    __slots__ = ['_ffi','_libpcap','_base','_pcapdev','_user_callback']

    def __init__(self, filename, filterstr=None):
        self._base = _PcapFfi.instance()
        self._ffi = self._base.ffi
        self._libpcap = self._base.lib
        self._user_callback = None

        errbuf = self._ffi.new("char []", 128)
        pcap = self._libpcap.pcap_open_offline(bytes(filename, 'ascii'), errbuf)
        if pcap == self._ffi.NULL:
            raise PcapException("Failed to open pcap file for reading: {}: {}".format(filename, self._ffi.string(errbuf)))
        
        dl = self._libpcap.pcap_datalink(pcap)
        try:
            dl = Dlt(dl)
        except ValueError as e:
            raise PcapException("Don't know how to handle datalink type {}".format(dl))
        self._pcapdev = PcapDev(dl, 0, 0, _PcapFfi.instance().version, pcap)

        if filterstr is not None:
            self._base._set_filter(pcap, filterstr)

    def close(self):
        self._libpcap.pcap_close(self._pcapdev.pcap)

    def recv_packet(self):
        return self._base._recv_packet(self._pcapdev.pcap)

    def set_filter(self, filterstr):
        self._base._set_filter(self._pcapdev.pcap, filterstr)

    def dispatch(self, callback, count=-1):
        self._user_callback = callback
        handle = self._ffi.new_handle(self)
        rv = self._libpcap.pcap_dispatch(self._pcapdev.pcap, count, _pcap_callback, handle)
        return rv

    def loop(self, callback, count=-1):
        self._user_callback = callback
        handle = self._ffi.new_handle(self)
        rv = self._libpcap.pcap_loop(self._pcapdev.pcap, count, _pcap_callback, handle)

    def _callback(self, pkt):
        self._user_callback(pkt)

    def breakloop(self):
        self._libpcap.pcap_breakloop(self._pcapdev.pcap)


class PcapLiveDevice(object):
    '''
    Class the represents a live pcap capture/injection device.
    '''
    _OpenDevices = {} # objectid -> low-level pcap dev
    _lock = Lock()
    __slots__ = ['_ffi','_libpcap','_base','_pcapdev','_devname','_fd','_user_callback']

    def __init__(self, device, snaplen=65535, promisc=1, to_ms=100, 
                 filterstr=None, nonblock=True, only_create=False):
        self._base = _PcapFfi.instance()
        self._ffi = self._base.ffi
        self._libpcap = self._base.lib
        self._fd = None
        self._user_callback = None

        errbuf = self._ffi.new("char []", 128)
        internal_name = None
        for dev in self._base._interfaces:
            if dev.name == device:
                internal_name = dev.internal_name
                break
        if internal_name is None:
            raise Exception("No such device {} exists.".format(device))
        self._devname = device
        self._pcapdev = None

        if only_create:
            pcap = self._libpcap.pcap_create(bytes(internal_name, 'ascii'), errbuf)
            self._pcapdev = PcapDev(0, 0, 0, _PcapFfi.instance().version, pcap)
            with PcapLiveDevice._lock:
                PcapLiveDevice._OpenDevices[id(self)] = pcap
            if pcap == self._ffi.NULL:
                raise PcapException("Failed to open live device {}: {}".format(internal_name, self._ffi.string(errbuf)))
            return

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

        self._pcapdev = PcapDev(dl, nblock, snaplen, _PcapFfi.instance().version, pcap)
        self._fd = self._libpcap.pcap_get_selectable_fd(self._pcapdev.pcap)

        with PcapLiveDevice._lock:
            PcapLiveDevice._OpenDevices[id(self)] = self._pcapdev.pcap

        if filterstr is not None:
            self.set_filter(filterstr)

    @staticmethod
    def create(device):
        return PcapLiveDevice(device, only_create=True)

    def activate(self):
        rv = self._libpcap.pcap_activate(self._pcapdev.pcap) 
        if rv < 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error activating: {} {}".format(rv, s))

        warning = 0
        if rv > 0:
            warning = PcapWarning(rv)

        self._pcapdev = PcapDev(self.dlt, self.blocking, self.snaplen, 
                _PcapFfi.instance().version, self._pcapdev.pcap)
        return warning

    @property
    def blocking(self):
        errbuf = self._ffi.new("char []", 128)
        rv = self._libpcap.pcap_getnonblock(self._pcapdev.pcap, errbuf)
        if rv != 0:
            raise PcapException("Error getting nonblock state: {}".format(self._ffi.string(errbuf)))
        return bool(rv)

    @blocking.setter
    def blocking(self, value):
        errbuf = self._ffi.new("char []", 128)
        rv = self._libpcap.pcap_setnonblock(self._pcapdev.pcap, int(value), errbuf)
        if rv != 0:
            raise PcapException("Error setting nonblock state: {}".format(self._ffi.string(errbuf)))

    @property
    def snaplen(self):
        return self._libpcap.pcap_snapshot(self._pcapdev.pcap)

    @snaplen.setter
    def snaplen(self, value):
        rv = self._libpcap.pcap_set_snaplen(self._pcapdev.pcap, int(value))
        if rv != 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting snaplen: {}".format(s))

    def set_promiscuous(self, value):
        rv = self._libpcap.pcap_set_promisc(self._pcapdev.pcap, int(value))
        if rv != 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting promiscuous mode: {}".format(s))

    def set_timeout(self, value): 
        rv = self._libpcap.pcap_set_timeout(self._pcapdev.pcap, int(value))
        if rv != 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting timeout value: {}".format(s))

    def set_buffer_size(self, value): 
        rv = self._libpcap.pcap_set_buffer_size(self._pcapdev.pcap, int(value))
        if rv != 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting buffer size: {}".format(s))

    def set_immediate_mode(self, value):
        rv = self._libpcap.pcap_set_immediate_mode(self._pcapdev.pcap, int(value))
        if rv != 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting immediate mode: {}".format(s))

    def list_tstamp_types(self):
        errbuf = self._ffi.new("char []", 128)
        ppint = self._ffi.new("int * *")
        rv = self._libpcap.pcap_list_tstamp_types(self._pcapdev.pcap, ppint)
        if rv < 0:
            raise PcapException("Error getting tstamp type list: {}".format(self._ffi.string(errbuf)))

        xints = ppint[0]
        tstamptypes = []
        for i in range(rv):
            tstamptypes.append(PcapTstampType(xints[i]))

        self._libpcap.pcap_free_tstamp_types(xints)
        return tstamptypes

    def set_tstamp_type(self, value): 
        value = PcapTstampType(value)
        valid_types = self.list_tstamp_types()
        if value not in valid_types:
            raise PcapException("Not a valid tstamp type for this device (see list_tstamp_types)")
        rv = self._libpcap.pcap_set_tstamp_type(self._pcapdev.pcap, int(value))
        if rv != 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting timestamp type: {}".format(s))

    @property
    def tstamp_precision(self):
        val = self._libpcap.pcap_get_tstamp_precision(self._pcapdev.pcap)
        return PcapTstampPrecision(val)

    @tstamp_precision.setter
    def tstamp_precision(self, value):
        value = PcapTstampPrecision(value)
        rv = self._libpcap.pcap_set_tstamp_precision(self._pcapdev.pcap, int(value))
        if rv != 0:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting timestamp precision: {}".format(s))

    @staticmethod
    def set_bpf_filter_on_all_devices(filterstr):
        '''
        Long method name, but self-explanatory.  Set the bpf
        filter on all devices that have been opened.
        '''
        with PcapLiveDevice._lock:
            for dev in PcapLiveDevice._OpenDevices.values():
                _PcapFfi.instance()._set_filter(dev, filterstr)

    @property
    def dlt(self):
        dl = self._libpcap.pcap_datalink(self._pcapdev.pcap)
        try:
            rv = Dlt(dl)
            return rv
        except:
            raise PcapException("Don't know how to handle datalink type {}".format(dl))

    @property
    def fd(self):
        if self._fd is not None:
            return self._fd
        try:
            fd = self._libpcap.pcap_get_selectable_fd(self._pcapdev.pcap)
            self._fd = fd
            return fd
        except:
            s = self._ffi.string(self._libpcap.pcap_geterr(xpcap))
            raise PcapException("Error getting select fd: {}".format(s))

    @property
    def name(self):
        return self._devname

    def send_packet(self, xbuffer):
        if not isinstance(xbuffer, bytes):
            raise PcapException("Packets to be sent via libpcap must be serialized as a bytes object")
        xlen = len(xbuffer)
        rv = self._libpcap.pcap_sendpacket(self._pcapdev.pcap, xbuffer, xlen)
        if rv == 0:
            return True
        s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
        raise PcapException("Error sending packet: {}".format(s))

    def recv_packet_or_none(self):
        return self._base._recv_packet(self._pcapdev.pcap)

    def dispatch(self, callback, count=-1):
        self._user_callback = callback
        handle = self._ffi.new_handle(self)
        rv = self._libpcap.pcap_dispatch(self._pcapdev.pcap, count, _pcap_callback, handle)
        return rv

    def loop(self, callback, count=-1):
        self._user_callback = callback
        handle = self._ffi.new_handle(self)
        rv = self._libpcap.pcap_loop(self._pcapdev.pcap, count, _pcap_callback, handle)

    def _callback(self, pkt):
        self._user_callback(pkt)

    def breakloop(self):
        self._libpcap.pcap_breakloop(self._pcapdev.pcap)

    def recv_packet(self, timeout):
        # FIXME: ugly and long
        if timeout is None or timeout < 0:
            timeout = None

        if self._fd >= 0:
            try:
                xread,xwrite,xerr = select([self._fd], [], [self._fd], timeout)
            except:
                return None
            if xread:  
                return self._base._recv_packet(self._pcapdev.pcap)
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
                    pkt = self._base._recv_packet(self._pcapdev.pcap)
                    if pkt:
                        return pkt
                    now = time()
                # after all that, still got nothing.
                return None
            else:
                return self._base._recv_packet(self._pcapdev.pcap)
        else:
            # no select, no non-blocking mode.  block away, my friend.
            return self._base._recv_packet(self._pcapdev.pcap)

    def close(self):
        with PcapLiveDevice._lock:
            xid = id(self)
            del PcapLiveDevice._OpenDevices[xid]
        self._libpcap.pcap_close(self._pcapdev.pcap)

    def stats(self):
        pstat = self._ffi.new("struct pcap_stat *")
        rv = self._libpcap.pcap_stats(self._pcapdev.pcap, pstat)
        if rv == 0:
            return PcapStats(pstat.recv,pstat.drop,pstat.ifdrop)
        else:
            s = self._ffi.string(self._libpcap.pcap_geterr(xpcap))
            raise PcapException("Error getting stats: {}".format(s))

    def set_filter(self, filterstr):
        self._base._set_filter(self._pcapdev.pcap, filterstr)

    def set_direction(self, direction):
        rv = self._libpcap.pcap_setdirection(self._pcapdev.pcap, int(direction))
        if rv == 0:
            return 
        else:
            s = self._ffi.string(self._libpcap.pcap_geterr(self._pcapdev.pcap))
            raise PcapException("Error setting direction: {}".format(s))


_PcapFfi() # instantiate singleton

xffi = _PcapFfi.instance().ffi
@xffi.callback("void(*)(unsigned char *, const struct pcap_pkthdr *, const unsigned char *)")
def _pcap_callback(handle, phdr, pdata):
    xhandle = xffi.cast("void *", handle)
    pcapobj = xffi.from_handle(xhandle)
    rawpkt = bytes(xffi.buffer(pdata, phdr[0].caplen))
    # dt = datetime.fromtimestamp(phdr[0].tv_sec)
    usec = int(xffi.cast("int", phdr[0].tv_usec))
    # ts = dt.replace(microsecond=usec)
    ts = float("{}.{:06d}".format(phdr[0].tv_sec, usec))
    pkt = PcapPacket(ts, phdr[0].caplen, phdr[0].len, rawpkt)
    pcapobj._callback(pkt)


if __name__ == '__main__':
    print ("Found devices: ")
    for dev in pcap_devices():
        print(str(dev)) 
