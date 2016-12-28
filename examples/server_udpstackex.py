#!/usr/bin/env python3
import socket
HOST = '127.0.0.1'
PORT = 10000
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((HOST, PORT))
print("Server waiting on port {} for a message to echo back".format(PORT))
data,addr = s.recvfrom(1024)
print("Received {} from {}".format(repr(data), repr(addr)))
x = s.sendto(data, (addr[0],addr[1]))
s.close()

