import socket
import sys
from tls00 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.connect(server_address)

aes = Aes()
aes.setKey(23)

try:
    message = aes.enc('Hello crypt world')
    print 'Encrypted:' + message
    sock.sendall(message)
    data = aes.enc(sock.recv(len(message)))
    print 'Received: ' + data
finally:
    sock.close()
