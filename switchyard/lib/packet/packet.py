from abc import ABCMeta, abstractmethod
from copy import deepcopy

from ..logging import log_warn
from ..exceptions import *

class Packet(object):
    '''
    Base class for packet headers.
    '''
    __slots__ = ['_headers','_raw']

    def __init__(self, raw=None, first_header=None):
        self._headers = []
        self._raw = None
        if raw:
            self._raw = raw
            self._parse(raw, first_header)            

    def __len__(self):
        '''Return the packed length of this packet, and all
        subsequent headers and payloads.'''
        return self.size()

    def size(self):
        '''Return the packed length of this header'''
        return sum([len(ph) for ph in self._headers])

    def to_bytes(self):
        '''
        Returns serialized bytes object representing all headers/
        payloads in this packet'''
        rawlist = []
        i = len(self._headers)-1
        while i >= 0:
            self._headers[i].pre_serialize(b''.join(rawlist), self, i)
            rawlist.insert(0, self._headers[i].to_bytes())
            i -= 1
        self._raw = b''.join(rawlist)
        return self._raw

    def _parse(self, raw, next_cls):
        '''
        Parse a raw bytes object and construct the list of packet header
        objects (and possible remaining bytes) that are part of this packet.
        '''
        if next_cls is None:
            from switchyard.lib.packet import Ethernet
            next_cls = Ethernet

        self._headers = []
        while issubclass(next_cls, PacketHeaderBase):
            packet_header_obj = next_cls()
            raw = packet_header_obj.from_bytes(raw)
            self.add_header(packet_header_obj)
            next_cls = packet_header_obj.next_header_class()
            if next_cls is None:
                break
        if raw:
            self.add_header(RawPacketContents(raw))

    @staticmethod
    def from_bytes(raw, first_header):
        '''Create a new packet by parsing the contents of a bytestring'''
        p = Packet(raw, first_header)        
        return p

    def __iadd__(self, ph):
        '''Add the packet header to the end of this packet; return
           this packet header.  Only += (iadd) is defined, since 
           this method is inherently mutating.'''
        if not isinstance(ph, (PacketHeaderBase, bytes)):
            raise Exception("Invalid operand type for +: can't add {} to a Packet".format(type(ph)))
        self.add_header(ph)
        return self

    def __add__(self, pobj):
        if isinstance(pobj, Packet):
            p = deepcopy(self)
            for header in pobj:
                p.add_header(header)
            return p
        elif isinstance(pobj, (PacketHeaderBase, bytes)):
            p = deepcopy(self)
            p.add_header(pobj)
            return p
        else:
            raise Exception("Invalid operand type for +: can't add {} and {} together".format(type(self), type(pobj)))

    def headers(self):
        '''
        Return a list of packet header names in this packet.
        '''
        return [ ph.__class__.__name__ for ph in self._headers ]

    def num_headers(self):
        '''
        Return the number of headers in the packet.
        '''
        return len(self._headers)

    def prepend_header(self, ph):
        '''
        Insert a PacketHeader object at the beginning of this packet
        (i.e., as the first header of the packet).
        '''
        self._headers.insert(0, ph)

    def add_header(self, ph):
        '''
        Add a PacketHeaderBase derived class object, or a raw bytes object
        as the next "header" item in this packet.  Note that 'header'
        may be a slight misnomer since the last portion of a packet is
        considered application payload and not a header per se.
        '''
        if isinstance(ph, bytes):
            ph = RawPacketContents(ph)
        if isinstance(ph, PacketHeaderBase):
            self._headers.append(ph)
            return self
        raise Exception("Payload for a packet header must be an object that is a subclass of PacketHeaderBase, or a bytes object.")

    def insert_header(self, idx, ph):
        '''
        Insert a PacketHeaderBase-derived object at index idx the list of headers.
        Any headers previously in the Packet from index idx:len(ph) are shifted to
        make room for the new packet.
        '''
        self._headers.insert(idx, ph)

    def add_payload(self, ph):
        '''Alias for add_header'''
        self.add_header(ph)

    def has_header(self, hdrclass):
        '''
        Return True if the packet has a header of the given hdrclass, 
        False otherwise.
        '''
        if isinstance(hdrclass, str):
            return self.get_header_by_name(hdrclass) is not None
        return self.get_header(hdrclass) is not None

    def get_header_by_name(self, hdrname):
        '''
        Return the header object that has the given (string) header
        class name.  Returns None if no such header exists.
        '''
        for hdr in self._headers:
            if hdr.__class__.__name__ == hdrname:
                return hdr
        return None

    def get_header(self, hdrclass, returnval=None):
        '''
        Return the first header object that is of
        class hdrclass, or None if the header class isn't
        found.
        '''
        if isinstance(hdrclass, str):
            return self.get_header_by_name(hdrclass)

        for hdr in self._headers:
            if isinstance(hdr, hdrclass):
                return hdr
        return returnval

    def get_header_index(self, hdrclass, startidx=0):
        '''
        Return the first index of the header class hdrclass
        starting at startidx (default=0), or -1 if the
        header class isn't found in the list of headers.
        '''
        for hdridx in range(startidx, len(self._headers)):
            if isinstance(self._headers[hdridx], hdrclass):
                return hdridx
        return -1

    def __iter__(self):
        return iter(self._headers)

    def _checkidx(self, index):
        if isinstance(index, int):
            if index < 0:
                index = len(self._headers) + index
            if not (0 <= index < len(self._headers)):
                raise IndexError("Index out of range")
            return index
        
    def __getitem__(self, index):
        if isinstance(index, int):
            index = self._checkidx(index)
            return self._headers[index]
        elif isinstance(index, type) and issubclass(index, PacketHeaderBase):
            idx = self.get_header_index(index)
            if idx == -1:
                raise KeyError("No such header type exists.")
            return self._headers[idx]
        else:
            raise IndexError("Indexes must be integers or header class names")

    def __setitem__(self, index, value):
        if not isinstance(index, int):
            raise TypeError("Index must be an integer")
        index = self._checkidx(index)
        if not isinstance(value, (PacketHeaderBase, bytes)):
            raise TypeError("Can't assign a non-packet header in a packet")
        self._headers[index] = value

    def __contains__(self, obj):
        for ph in self._headers:
            if ph is obj or \
                (isinstance(obj, ph.__class__) and ph == obj):
                return True
        return False

    def __delitem__(self, index):
        if isinstance(index, int):
            index = self._checkidx(index)
            del self._headers[index]
        elif isinstance(index, type) and issubclass(index, PacketHeaderBase):
            idx = self.get_header_index(index)
            if idx == -1:
                raise KeyError("No such header type exists.")
            del self._headers[idx]
        else:
            raise IndexError("Indexes must be integers or header class names")

    def __eq__(self, other):
        if not isinstance(other, Packet):
            raise TypeError("Can't compare Packet with non-Packet for equality")
        if len(self.headers()) != len(other.headers()):
            return False
        for i in range(len(other.headers())):
            if not isinstance(other[i], self[i].__class__) \
                    or self[i] != other[i]:
                return False
        return True

    def __str__(self):
        return ' | '.join([str(ph) for ph in self._headers if isinstance(ph, PacketHeaderBase)])


class PacketHeaderBase(metaclass=ABCMeta):
    '''
    Base class for packet headers.
    '''
    __slots__ = []
    _next_header_map = {}
    _next_header_class_key = ''

    def __init__(self, **kwargs):
        for attrname, value in kwargs.items():
            setattr(self, attrname, value)

    def __len__(self):
        '''Return the packed length of this packet; calls
        abstract method size(), which must be overridden in
        derived classes.'''
        return self.size()

    def size(self):
        '''Returns the number of bytes that the header would consist of when serialized to wire format'''
        return len(self.to_bytes())

    @classmethod
    def set_next_header_class_key(cls, attr):
        '''Indicate which attribute is used to decide the type of packet
           header that comes after this one.  For example, the IPv4
           protocol attribute.'''
        cls._next_header_class_key = attr

    @classmethod
    def add_next_header_class(cls, attr, hdrcls):
        '''Add a new mapping between a next header type value and a Python
        class that implements that header type.'''
        cls._next_header_map[attr] = hdrcls

    @classmethod
    def set_next_header_map(cls, mapdict):
        '''(Re)initialize a dictionary that maps a "next header type" attribute
        to a Python class that implements that header type.'''
        cls._next_header_map = mapdict

    def next_header_class(self):
        '''Return class of next header, if known.'''
        if self._next_header_class_key == '':
            return None
        key = getattr(self, self._next_header_class_key)
        rv = self._next_header_map.get(key, None)
        if rv is None:
            log_warn("No class exists to handle next header value {}".format(key))
        return rv

    def pre_serialize(self, raw, packet, i):
        '''
        This method is called by the Switchyard framework just before any
        subsequent packet headers (i.e., headers that come *after* this one)
        are serialized into a byte sequence.  The main purpose for this callback
        is to allow the header to compute its checksum, especially if it needs
        access to header fields that are outside its scope (e.g., in IPv6,
        the checksum includes the IPv6 source/dst addresses).

        The three parameters to this method are the raw (bytes) representation
        of the "tail" of the packet (i.e., headers that come after this one),
        a reference to the full packet object, and the index of the current header.
        This method should not return anything.
        '''
        pass

    @abstractmethod
    def to_bytes(self):
        '''Return a 'packed' byte-level representation of this packet header.'''
        return b''

    @abstractmethod
    def from_bytes(self, raw):
        '''
        Reconstruct the attributes of a header given the bytes object named raw.  The method returns any bytes that are *not* used to reconstruct a header.  An exception (typically a ValueError) is raised if there is some kind of problem deserializing the bytes object into packet header attributes.
        '''
        pass

    def __add__(self, ph):
        '''Add two packet headers together to get a new packet object.'''
        if not TypeError(ph, (bytes, PacketHeaderBase)):
            raise Exception("Only objects derived from PacketHeaderBase and bytes objects can be added to create a new packet.")
        p = Packet()
        p.add_header(self)
        p.add_header(ph)
        return p

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
            self.to_bytes() == other.to_bytes()

    def __str__(self):
        return self.__class__.__name__


class NullPacketHeader(PacketHeaderBase):
    def __init__(self):
        PacketHeaderBase.__init__(self)

    def to_bytes(self):
        return b''

    def from_bytes(self, raw):
        return raw

    def __getattr__(self, attr):
        return self

    def __call__(self, *args, **kwargs):
        return self

    def __str__(self):
        return 'NullPacketHeader'

    def __eq__(self, other):
        return isinstance(self, other.__class__) 

    def __repr__(self):
        return 'NullPacketHeader()'


class RawPacketContents(PacketHeaderBase):
    __slots__ = ['_raw'] 

    def __init__(self, raw=None):
        if isinstance(raw, str):
            raw = bytes(raw, 'utf8')
        elif isinstance(raw, bytes):
            pass
        else:
            raise TypeError("RawPacketContents must be initialized with either str or bytes.  You gave me {}".format(raw.__class__.__name__))
        self._raw = raw

    def to_bytes(self):
        return self._raw    

    @property
    def data(self):
        return self._raw

    def from_bytes(self, raw):
        if isinstance(raw, bytes):
            self._raw = bytes(raw)
        elif isinstance(raw, str):
            self._raw = bytes(raw, 'utf8')
        else:
            raise TypeError("RawPacketContents must be initialized with either str or bytes.  You gave me {}".format(raw.__class__.__name__))

    def size(self):
        return len(self._raw)

    def __eq__(self, other):
        return isinstance(self, other.__class__) and \
            self.to_bytes() == other.to_bytes()

    def __str__(self):
        ellipse = '...'
        if len(self._raw) < 10:
            ellipse = ''
        return '{} ({} bytes) {}{}'.format(self.__class__.__name__,
            len(self._raw), self._raw[:10], ellipse)
