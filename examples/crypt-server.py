# crypt-server.py
#
# Copyright (C) 2006-2017 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

import socket
import sys
sys.path.append('./crypt')
from crypt0 import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 11111)
sock.bind(server_address)
sock.listen(1)

crypt = Crypt0(12345)

while True:
    connection, client_address = sock.accept()
    try:
        cipher = connection.recv(32)
        if cipher:
            print 'Received: ' + cipher
            plain = crypt.encrypt(cipher)
            print 'Decrypted:' + plain
            connection.sendall(crypt.encrypt("I hear you fa shizzle!"))
        else:
            break
    finally:
        connection.close()
