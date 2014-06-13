from abc import ABCMeta, abstractmethod

class PacketHeaderBase(object):
    '''
    Base class for packet headers.
    '''
    __metaclass__ = ABCMeta
    __slots__ = ['__next']

    def __init__(self):
        self.__next = None

    @abstractmethod
    def __len__(self):
        return 0

    @abstractmethod
    def serialize(self):
        '''
        Abstract method; returns serialized bytes object representing packet
        header contents.
        '''
        pass

    def pack(self):
        '''
        Alias for serialize
        '''
        return self.serialize()

    @classmethod
    @abstractmethod
    def parse(self, raw):
        '''
        Parse a header from raw bytes; return PacketBase subclass
        (e.g., a concrete packet header object)
        '''
        pass

    def addHeader(self, ph):
        '''
        Add the packet header object represented by ph as
        the next header in this packet.
        '''
        self.__next = ph
        return ph

    @property
    def next(self):
        '''
        Return next header in this packet.
        '''
        return self.__next

    def nextHeader(self):
        '''Alias for next'''
        return self.next

    @property
    def payload(self):
        '''Alias for next'''
        return self.next

    @next.setter
    def next(self, ph):
        '''Set next header in this packet'''
        self.addHeader(ph)

    def __add__(self, ph):
        '''Alias for set next header in packet'''
        self.addHeader(ph)
        return ph

    @payload.setter
    def payload(self, ph):
        '''Alias for set next header in packet'''
        self.addHeader(ph)

    def __iter__(self):
        return self

    def __next__(self):
        if not self.next:
            raise StopIteration()
        return self.next


