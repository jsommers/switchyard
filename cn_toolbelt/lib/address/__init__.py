__author__ = 'jsommers@colgate.edu'

from netaddr import *
IPAddr = IPAddress

def EthAddr(addr="00:00:00:00:00:00"):
    return EUI(addr)

ethaddr = EthAddr
