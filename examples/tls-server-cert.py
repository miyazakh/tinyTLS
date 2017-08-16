import socket
import sys
sys.path.append('./tls')
from tls0_cert import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

svCert = Cert0()
f = open("./certs/svCert.json")
svCert.load(f)
f = open("./certs/svKey.json")
svKey = RsaPrivate(json.load(f))

tls = Tls0_cert(svCert, svKey)

while True:
    connection, client_address = sock.accept()
    tls.accept(connection, True)
    try:
        data = tls.recv(32)
        if data:
            print 'received: ' + data
            tls.send("I hear you fa shizzle!")
        else:
            break
    finally:
        connection.close()
