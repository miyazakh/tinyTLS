import socket
import sys
sys.path.append('./crypt')
from crypt0 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

aes = Aes0(12345)

while True:
    connection, client_address = sock.accept()
    try:
        while True:
            data = connection.recv(32)
            if data:
                print 'Received: ' + data
                dec = aes.encrypt(data)
                print 'Decrypted:' + dec
                connection.sendall(aes.encrypt("I hear you fa shizzle!"))
            else:
                break
    finally:
        # Clean up the connection
        connection.close()
