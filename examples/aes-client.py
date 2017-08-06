import socket
import sys
sys.path.append('./crypt')
from crypt0 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.connect(server_address)

aes = Aes0(12345)

try:
    message = aes.encrypt('Hello crypt world')
    print 'Encrypted:' + message
    sock.sendall(message)
    data = aes.encrypt(sock.recv(len(message)))
    print 'Received: ' + data
finally:
    sock.close()
