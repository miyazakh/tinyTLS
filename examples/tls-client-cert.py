import socket
import sys
sys.path.append('./tls')
from tls0_cert import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.connect(server_address)

caCert = Cert0()
f = open("./certs/caCert.json")
caCert.load(f)
tls = Tls0_cert(peerC=caCert)
tls.connect(sock, True)

message = tls.send('Hello server')
data = tls.recv(32)
print 'received:' + data
sock.close()