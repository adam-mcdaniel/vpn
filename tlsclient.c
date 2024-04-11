#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define CHK_SSL(err)               \
	if ((err) < 1)                  \
	{                               \
		ERR_print_errors_fp(stderr); \
		exit(2);                     \
	}

#define CA_FILE "localhost.crt"
#define CA_DIR "cert_client"

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555

int createTunDevice(int tunID)
{
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	char device_name[IFNAMSIZ];
	sprintf(device_name, "tun%d", tunID);
	strncpy(ifr.ifr_name, device_name, IFNAMSIZ);

	if ((tunfd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		perror("open");
		exit(1);
	}

	ioctl(tunfd, TUNSETIFF, &ifr);
	printf("Created device %s\n", ifr.ifr_name);
	return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	// printf("Got a packet from TUN\n");
	
	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	buff[len] = 0;
	SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, int sockfd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];


	bzero(buff, BUFF_SIZE);
	len = SSL_read(ssl, buff, BUFF_SIZE);
	buff[len] = 0;
	printf("Got a message from the tunnel: %s\n", buff);
	write(tunfd, buff, len);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);

	if (preverify_ok == 1)
	{
		printf("Certificate for '%s' verification success!\n", buf);
	}
	else
	{
		int err = X509_STORE_CTX_get_error(x509_ctx);
		printf("Certificate verification failed: %s.\n",
				 X509_verify_cert_error_string(err));
	}
}

SSL *setupTLSClient(const char *hostname)
{
	// Step 0: OpenSSL library initialization
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	meth = (SSL_METHOD *)TLSv1_2_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	if (SSL_CTX_load_verify_locations(ctx, CA_FILE, CA_DIR) < 1)
	{
		printf("Error setting the verify locations: %s/%s\n", CA_DIR, CA_FILE);
		exit(0);
	}
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}

int setupTCPClient(const char *hostname, int port)
{
	struct sockaddr_in server_addr;

	// Get the IP address from hostname
	struct hostent *hp = gethostbyname(hostname);

	// Create a TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information (IP, port #, and family)
	memset(&server_addr, '\0', sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	//   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14");
	server_addr.sin_port = htons(port);
	server_addr.sin_family = AF_INET;

	// Connect to the destination
	connect(sockfd, (struct sockaddr *)&server_addr,
			  sizeof(server_addr));

	return sockfd;
}

int login(SSL *ssl)
{
	char username[1024];

	printf("Enter username: ");
	scanf("%s", username);
	getchar();
	char *password = getpass("Enter password: ");

	printf("Sending username: %s\n", username);
	printf("Sending password: ");
	for (int i = 0; i < strlen(password); i++)
		printf("*");
	printf("\n");
	SSL_write(ssl, username, strlen(username));
	SSL_write(ssl, password, strlen(password));

	char buf[9000];
	int len = SSL_read(ssl, buf, sizeof(buf) - 1);
	buf[len] = 0;

	if (strcmp(buf, "OK") == 0)
	{
		return 1;
	}
	else if (strcmp(buf, "FAIL") == 0)
	{
		return 0;
	}
	else
	{
		printf("Error: %s", buf);
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	char *hostname = "yahoo.com";
	int port = 443;

	if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);

	printf("Hostname: %s\nPort: %d\n", hostname, port);
	/*----------------Create Tunnel device ----------------*/
	int tunfd = createTunDevice(0);

	/*----------------TLS initialization ----------------*/
	SSL *ssl = setupTLSClient(hostname);

	/*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);

	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	int err = SSL_connect(ssl);
	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*----------------Authenticate------------------------*/
	if (!login(ssl))
	{
		printf("Login failed\n");
		exit(1);
	}
	else
	{
		printf("Login successful\n");
	}

	/*----------------Send/Receive data --------------------*/
	char buf[9000];
	char sendBuf[200];

	while (1)
	{
		fd_set readFDSet;
		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet))
			tunSelected(tunfd, sockfd, ssl);

		if (FD_ISSET(sockfd, &readFDSet))
			socketSelected(tunfd, sockfd, ssl);
	}
}
