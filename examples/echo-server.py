import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

while True:
    connection, client_address = sock.accept()
    try:
        while True:
            data = connection.recv(32)
            if data:
                print 'received: ' + data
                connection.sendall("I hear you fa shizzle!")
            else:
                break
    finally:
        connection.close()
