import socket
import sys
from tls00 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.bind(server_address)
sock.listen(1)

tls = tTls()

connection, client_address = sock.accept()
tls.accept(connection)
while True:
    data = tls.recv(32)
    if data:
        print 'received: ' + data
        tls.send(data)
    else:
        break
connection.close()
