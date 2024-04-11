all: 
	gcc -o vpnserver src/vpnserver.c
	gcc -o vpnclient src/vpnclient.c
	gcc -o tlsclient src/tlsclient.c -lssl -lcrypto 
	gcc -o tlsserver src/tlsserver.c -lssl -lcrypto -lcrypt
	gcc -o login src/login.c -lssl -lcrypto -lcrypt

clean: 
	rm vpnserver vpnclient tlsclient tlsserver login
