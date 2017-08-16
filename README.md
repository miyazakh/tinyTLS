# Tiny TLS

### File organization

./certs  
    Certificates, keyfiles for examples

./crypt/crypt0.py  
    Crypt layer class  

./tls  

    ./tls/tls0.py  
       TLS layer class  
    ./tls/tls0_cert.py  
        TLS layer with Certificate class
    ./tls/tls_rec.py  
        TLS record layer class  

./examples  

   echo-{client, server}.py  
    basic echo client and server

   crypt-{client, server}.py  
     echo client and server, message encrypted by Crypt0

   tls-{client, server}.py  
    echo client and server with TLS0 protocol

   tls-{client, server}-cert.py  
     echo client and server with TLS0 protocol with Certificate

./test   

   testing crypt layer classes  

   test0.py  
   test-crypt0.py  
   test-dh.py  
   test-rsa.py  
   test-sign0.py  
   test-sign1.py  


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
