import socket
import sys
from tls0 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

svCert = Cert0()
f = open("svCert.json")
svCert.load(f)
f = open("svKey.json")
svKey = RsaPrivate(json.load(f))

tls = Tls0(svCert, svKey)

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
