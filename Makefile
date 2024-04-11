all: 
	gcc -o vpnserver vpnserver.c
	gcc -o vpnclient vpnclient.c
	gcc -o tlsclient tlsclient.c -lssl -lcrypto 
	gcc -o tlsserver tlsserver.c -lssl -lcrypto -lcrypt
	gcc -o login login.c -lssl -lcrypto -lcrypt

clean: 
	rm vpnserver vpnclient tlsclient tlsserver login
