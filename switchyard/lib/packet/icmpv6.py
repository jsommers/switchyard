import struct
from ipaddress import IPv6Address
from switchyard.lib.packet.icmp import ICMP, ICMPEchoRequest, ICMPEchoReply
from switchyard.lib.packet.common import ICMPv6Type, ICMPv6TypeCodeMap
from switchyard.lib.packet.common import checksum as csum

'''
References:
    http://tools.ietf.org/html/rfc4443
    Stevens, Fall, TCP/IP Illustrated, Vol 1., 2nd Ed.
'''


class ICMPv6(ICMP):
    def __init__(self, **kwargs):
        self._valid_types = ICMPv6Type
        self._valid_codes_map = ICMPv6TypeCodeMap
        self._classtype_from_icmptype = ICMPv6ClassFromType
        self._icmptype_from_classtype = ICMPv6TypeFromClass
        self._type = self._valid_types.EchoRequest
        self._code = self._valid_codes_map[self._type].EchoRequest
        self._icmpdata = ICMPv6ClassFromType(self._type)()
        self._checksum = 0
        super().__init__(**kwargs)

    def checksum(self):
        return self._checksum

    def _compute_checksum(self, srcip, dstip, raw):
        sep = b''
        databytes = self._icmpdata.to_bytes()
        icmpsize = ICMP._MINLEN+len(databytes)
        self._checksum = csum(sep.join( (srcip.packed, dstip.packed,
            struct.pack('!I3xBBB', 
                ICMP._MINLEN+len(databytes), 58, self._type.value, self._code.value), 
            databytes) ))

    def pre_serialize(self, raw, pkt, i):
        ip6hdr = pkt.get_header('IPv6')
        assert(ip6hdr is not None)
        self._compute_checksum(ip6hdr.srcip, ip6hdr.dstip, raw)

class ICMPv6EchoRequest(ICMPEchoRequest):
    pass

class ICMPv6EchoReply(ICMPEchoReply):
    pass

class ICMPv6HomeAgentAddressDiscoveryRequestMessage(ICMPv6):
    pass

class ICMPv6HomeAgentAddressDiscoveryReplyMessage(ICMPv6):
    pass

class ICMPv6MobilePrefixSolicitation(ICMPv6):
    pass

class ICMPv6MobilePrefixAdvertisement(ICMPv6):
    pass

def construct_icmpv6_class_map():
    clsmap = {}
    for xtype in ICMPv6Type:
        clsname = "ICMPv6{}".format(xtype.name)
        try:
            cls = eval(clsname)
        except:
            cls = None
        clsmap[xtype] = cls
    def inner(icmptype):
        icmptype = ICMPv6Type(icmptype)
        return clsmap.get(icmptype, None)
    return inner

def construct_icmpv6_type_map():
    typemap = {}
    for xtype in ICMPv6Type:
        clsname = "ICMPv6{}".format(xtype.name)
        try:
            cls = eval(clsname)
            typemap[cls] = xtype
        except:
            pass
    def inner(icmpcls):
        return typemap.get(icmpcls, None)
    return inner    

ICMPv6ClassFromType = construct_icmpv6_class_map()
ICMPv6TypeFromClass = construct_icmpv6_type_map()
