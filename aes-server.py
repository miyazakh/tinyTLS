import socket
import sys
from tls00 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.bind(server_address)
sock.listen(1)

aes = Aes()
aes.key(23)

while True:
    connection, client_address = sock.accept()
    try:
        while True:
            data = aes.enc(connection.recv(32))
            if data:
                print 'received: ' + data
                connection.sendall(aes.enc(data))
            else:
                break
    finally:
        # Clean up the connection
        connection.close()
