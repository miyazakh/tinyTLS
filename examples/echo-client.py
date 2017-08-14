import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.connect(server_address)

try:
    sock.sendall('Hello server')
    data = sock.recv(32)
    print 'received:' + data

finally:
    print 'closing socket'
    sock.close()
