# import socket
import switchyard.lib.socketemu as socket

HOST = '149.43.80.25'
PORT = 10000
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print (s.family)
print (s.type)
print (s.proto)
s.settimeout(1.0)
s.sendto(b'Hello, world', (HOST,PORT))
data,addr = s.recvfrom(1024)
s.close()
print('Received', repr(addr),repr(data))

