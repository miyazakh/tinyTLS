import socket
import sys
from tls00 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.bind(server_address)
sock.listen(1)

aes = Aes()
aes.setKey(23)

while True:
    connection, client_address = sock.accept()
    try:
        while True:
            data = connection.recv(32)
            if data:
                print 'Received: ' + data
                dec = aes.enc(data)
                print 'Decrypted:' + dec
                connection.sendall(aes.enc(dec))
            else:
                break
    finally:
        # Clean up the connection
        connection.close()
