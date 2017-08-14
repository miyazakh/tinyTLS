import socket
import sys
sys.path.append('./crypt')
from crypt0 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

crypt = Crypt0(12345)

while True:
    connection, client_address = sock.accept()
    try:
        while True:
            cipher = connection.recv(32)
            if cipher:
                print 'Received: ' + cipher
                plain = crypt.encrypt(cipher)
                print 'Decrypted:' + plain
                connection.sendall(crypt.encrypt("I hear you fa shizzle!"))
            else:
                break
    finally:
        connection.close()
