import socket
import sys
sys.path.append('./tls')
from tls0 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

tls = Tls0()

while True:
    connection, client_address = sock.accept()
    tls.accept(connection, True)
    try:
        data = tls.recv()
        if data:
            print 'received: ' + data
            tls.send("I hear you fa shizzle!")
        else:
            break
    finally:
        connection.close()
