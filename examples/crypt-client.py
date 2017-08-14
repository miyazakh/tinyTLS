import socket
import sys
sys.path.append('./crypt')
from crypt0 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.connect(server_address)

crypt = Crypt0(12345)
cipher = crypt.encrypt('Hello server')
print 'Encrypted:' + cipher
sock.sendall(cipher)
plain = crypt.encrypt(sock.recv(32))
print 'Received: ' + plain

sock.close()
