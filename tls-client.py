import socket
import sys
from libttls import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.connect(server_address)

tls = Tls0()
tls.connect(sock)

message = tls.send('Hello TLS world')
data = tls.recv(32)
print 'received:' + data
sock.close()
