import socket
import sys
from libttls import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

tls = Tls0()

while True:
    connection, client_address = sock.accept()
    tls.accept(connection)
    try:
        while True:
            data = tls.recv(32)
            if data:
                print 'received: ' + data
                tls.send(data)
            else:
                break
    finally:
        connection.close()
