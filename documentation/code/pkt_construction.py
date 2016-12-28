from switchyard.lib.packet import *
p = Packet()   # construct a packet object
e = Ethernet() # construct Ethernet header
ip = IPv4()    # construct IPv4 header
icmp = ICMP()  # construct ICMP header
p += e         # add eth header to packet
p += ip        # add ip header to packet
p += icmp      # add icmp header to packet
print (p)
p = Ethernet() + IPv4() + ICMP()
p.num_headers()
len(p)
p.size()

p[0]
p[0].src
p[0].dst
p[0].dst = "ab:cd:ef:00:11:22"
str(p[0])
p[0].dst = EthAddr("00:11:22:33:44:55")
str(p[0])
p[0].ethertype
p[0].ethertype = EtherType.ARP
print (p)
p[0].ethertype = EtherType.IPv4 # set it back to sensible value

p.has_header(IPv4)
p.get_header_index(IPv4)
str(p[1]) # access by index
str(p[IPv4]) # access by header type
p[IPv4].protocol
p[IPv4].src
p[IPv4].dst
p[IPv4].dst = '149.43.80.13'

p.has_header(ICMP)
p.get_header_index(ICMP)
p[2] # access by index; notice no conversion to string
p[ICMP] # access by header type
p[ICMP].icmptype
p[ICMP].icmpcode
p[ICMP].icmpdata
icmp.icmpdata.sequence
icmp.icmpdata.identifier
icmp.icmpdata.identifier = 42
icmp.icmpdata.sequence = 13
print (p)

icmp.icmpdata.data = "hello, world"
print (p)

 p.to_bytes()

e = Ethernet(src="11:22:33:44:55:66", dst="66:55:44:33:22:11", ethertype=EtherType.IP)
ip = IPv4(src="1.2.3.4", dst="4.3.2.1", protocol=IPProtocol.UDP, ttl=32)
udp = UDP(src=1234, dst=4321)
p = e + ip + udp + b"this is some application payload!"
print(p)


