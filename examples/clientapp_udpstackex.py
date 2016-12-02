#!/usr/bin/env python3 

# import socket
import switchyard.lib.socket.socketemu as socket
import time

HOST = '127.0.0.1'
PORT = 10000
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)

s.sendto(b'Hello, world', (HOST,PORT))
try:
    print('Before recvfrom call')
    data,addr = s.recvfrom(1024)
    print('Received', repr(addr),repr(data))
except:
    print("Timeout")

print("Before close")
s.close()
print("After close")
