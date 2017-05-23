import socket
import sys
from tls00 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.connect(server_address)

tls = tTls()
tls.connect(sock)

message = tls.send('This is the message')
data = tls.recv(32)
print 'received:' + data
sock.close()
