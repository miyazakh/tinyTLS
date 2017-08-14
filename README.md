# Tiny TLS

### File organization

./certs  
    Certificates, keyfiles for examples

./crypt/crypt0.py  
    Crypt layer class  

./examples  

   echo-{client, server}.py  
    basic echo client and server

   crypt-{client, server}.py  
     echo client and server, message encrypted by Crypt0

   tls-{client, server}.py  
    echo client and server with TLS0 protocol

   tls-{client, server}-cert.py  
     echo client and server with TLS0 protocol with Certificate

./test/test0.py  
   testing crypt layer classes
./tls/tls0.py  
   TLS layer class
./tls/tls0_cert.py  
      TLS layer with Certificate class


### Quick start  

    $ git clone https://github.com/kojo1/tinyTLS  
    $ cd tinyTLS  
    $ python ./test/test0.py  

    $ python ./examples/echo-server.py &  
    $ python ./examples/echo-client.py

    $ python ./examples/crypt-server.py &  
    $ python ./examples/crypt-client.py

    $ python ./examples/tls-server.py &  
    $ python ./examples/tls-client.py

    $ python ./examples/tls-server-cert.py &  
    $ python ./examples/tls-client-cert.py

Enjoy!!
