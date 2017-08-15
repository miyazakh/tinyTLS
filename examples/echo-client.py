import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.connect(server_address)

sock.sendall('Hello server')
data = sock.recv(32)
print 'received:' + data

sock.close()
