#!/usr/bin/env python3 

# import socket
import switchyard.lib.socket as socket

HOST = '127.0.0.1'
PORT = 10000
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)

print("Sending message to server at {},{}".format(HOST,PORT))
s.sendto(b'Hello, stack', (HOST,PORT))
try:
    data,addr = s.recvfrom(1024)
    print('Client socket application received message from {}: {}'.format(repr(addr),data.decode('utf8')))
except:
    print("Timeout")

s.close()
