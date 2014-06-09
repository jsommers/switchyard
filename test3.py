from cn_toolbelt.lib.packet import Ethernet
from cn_toolbelt.lib.address import EthAddr, IPAddr

e = Ethernet()
e.src = '00:00:00:00:00:01'
e.dst = '11:00:00:11:00:11'
print e
