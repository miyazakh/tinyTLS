# tls_rec.py
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

# TLS Record Type
TlsRec_AppData = 23
TlsRec_Handshake = 22

TlsRec_ClientHello = 1
TlsRec_ServerHello = 2
TlsRec_Certificate = 11
TlsRec_ServerKeyExchange = 12
TlsRec_ClientKeyExchange = 16

class TlsRecord:
        def __init__(self, major=3, minor=3, dbg=None):
            """
                TLS Record layer class.
                Send and receive messages during handshake and applicatin messages

                Parameters
                ----------
                    major : TLS major version (TLS:3)
                    major : TLS minor version (SSLv3: 0, TLS1.0:1, TLS1.1:2, TLS1.2:3, TLS1.3:4)
            """
            self.dbg = dbg
            self.major = major
            self.minor = minor
        def setSock(self, s):
            """ set connected socket to use for sending/receiving messages """
            self.sock = s
        def send(self, msg):
            """ send handshake message """
            type = TlsRec_Handshake
            htype = TlsRec_ClientHello
            rec = chr(type) + chr(self.major) + chr(self.minor) + chr((len(msg) & 0xff00) >> 8) + (chr(len(msg) & 0xff))  + chr(htype) + msg
            self.sock.sendall(rec)
        def sendMsg(self, msg):
            """ send application message """
            type=TlsRec_AppData
            rec = chr(type) + chr(self.major) + chr(self.minor) + chr((len(msg) & 0xff00) >> 8) + (chr(len(msg) & 0xff)) + msg
            self.sock.sendall(rec)
        def recv(self):
            """
                Receive handshake message

                Returns
                -------
                str: received message
            """
            headerSz = 6
            rec = ''
            while len(rec) < 5:
                rec += self.sock.recv(5)
            sz = (ord(rec[3])<<8) + ord(rec[4])
            while sz > (len(rec)-headerSz):
                rec += self.sock.recv(sz)
            return rec[6:]
        def recvMsg(self):
            """
                Receive application message

                Returns
                -------
                str: received message
            """
            headerSz = 5
            rec = ''
            while len(rec) < 5:
                rec += self.sock.recv(5)
            sz = (ord(rec[3])<<8) + ord(rec[4])
            while sz > (len(rec)-headerSz):
                rec += self.sock.recv(sz)
            return rec[5:]
