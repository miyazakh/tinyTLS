import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.connect(server_address)

try:
    message = 'This is the message'
    sock.sendall(message)
    data = sock.recv(len(message))
    print 'received:' + data

finally:
    print 'closing socket'
    sock.close()
