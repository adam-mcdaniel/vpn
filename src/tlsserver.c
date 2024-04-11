#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <shadow.h>
#include <crypt.h>

#define TUNNEL 0

#define CHK_SSL(err)                 \
	if ((err) < 1)                   \
	{                                \
		ERR_print_errors_fp(stderr); \
		exit(2);                     \
	}
#define CHK_ERR(err, s) \
	if ((err) == -1)    \
	{                   \
		perror(s);      \
		exit(1);        \
	}

int setupTCPServer();					 // Defined in Listing 19.10
void processRequest(SSL *ssl, int sock); // Defined in Listing 19.12

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

	if (ioctl(tunfd, TUNSETIFF, &ifr) < 0)
	{
		perror("ioctl");
		exit(1);
	}

	printf("Created device %s\n", ifr.ifr_name);
	return tunfd;
}

int authenticate_username_and_password(char *user, char *passwd)
{
	printf("Authenticating login for user %s...\n", user);
	struct spwd *pw;
	char *epasswd;

	pw = getspnam(user);
	if (pw == NULL)
	{
		printf("User '%s' not found\n", user);
		return 0;
	}
	epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp) == 0)
	{
		printf("Successful login by %s!\n", user);
		return 1;
	}
	printf("Failed login by %s, incorrect password!\n", user);
	return 0;
}

int authenticate(SSL *ssl)
{
	printf("Authenticating user...\n");
	char username[1024], password[1024];
	int username_len = SSL_read(ssl, username, sizeof(username) - 1);
	int password_len = SSL_read(ssl, password, sizeof(password) - 1);

	int result = authenticate_username_and_password(username, password);

	if (result)
	{
		SSL_write(ssl, "OK", 2);
	}
	else
	{
		SSL_write(ssl, "FAIL", 4);
	}

	return result;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl)
{
	int len;
	char buff[9000];
	bzero(buff, 9000);
	len = read(tunfd, buff, 9000);
	buff[len] = '\0';
	
	printf("Reading from tunnel and writing to socket %d", sockfd);
	SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, int sockfd, SSL *ssl)
{
	int len;
	char buff[9000];
	bzero(buff, 9000);
	len = SSL_read(ssl, buff, 9000);
	buff[len] = '\0';

	// printf("Reading from socket %d and writing to tunnel", sockfd);
	write(tunfd, buff, len);
}

void pipeSelected(int tunfd, int pipefd)
{
	// initialise variables.
	int len;
	char buff[9000];
	bzero(buff, 9000);

	printf("Reading from pipe %d and writing to tunnel");

	// Read from TUN, write to pipe.
	len = read(tunfd, buff, 9000);
	buff[len] = '\0';
	write(pipefd, buff, len);
}

int main()
{
	printf("Starting server...\n");

	struct sockaddr_in sa_client;
	size_t client_len;
	int listen_sock = setupTCPServer();

	int tunfd = createTunDevice(TUNNEL);

	int pipefd[2];
	pipe(pipefd);
	if (fork() == 0)
	{
		while (1)
		{
			fd_set readFDSet;
			FD_ZERO(&readFDSet);
			FD_SET(tunfd, &readFDSet);
			select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
			if (FD_ISSET(tunfd, &readFDSet))
			{
				pipeSelected(tunfd, pipefd[1]);
			}
		}
		return 0;
	}
	else
	{
		while (1)
		{
			int sock = accept(listen_sock, (struct sockaddr *)&sa_client, &client_len);
			if (fork() == 0)
			{ // The child process
				close(listen_sock);

				SSL_METHOD *meth;
				SSL_CTX *ctx;
				SSL *ssl;

				// Step 0: OpenSSL library initialization
				// This step is no longer needed as of version 1.1.0.
				SSL_library_init();
				SSL_load_error_strings();
				SSLeay_add_ssl_algorithms();

				// Step 1: SSL context initialization
				meth = (SSL_METHOD *)TLSv1_2_method();
				ctx = SSL_CTX_new(meth);
				SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
				// Step 2: Set up the server certificate and private key
				SSL_CTX_use_certificate_file(ctx, "./cert_server/localhost.crt", SSL_FILETYPE_PEM);
				SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/localhost.key", SSL_FILETYPE_PEM);
				// Step 3: Create a new SSL structure for a connection
				ssl = SSL_new(ctx);

				SSL_set_fd(ssl, sock);
				int err = SSL_accept(ssl);
				CHK_SSL(err);
				printf("SSL connection established!\n");

				if (authenticate(ssl))
				{
					printf("Establishing VPN with client on tun%d\n", TUNNEL);

					while (1)
					{
						fd_set readFDSet;

						FD_ZERO(&readFDSet);
						FD_SET(sock, &readFDSet);
						FD_SET(pipefd[0], &readFDSet);
						select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

						if (FD_ISSET(pipefd[0], &readFDSet))
							tunSelected(pipefd[0], sock, ssl);

						if (FD_ISSET(sock, &readFDSet))
							socketSelected(tunfd, sock, ssl);
					}
				}

				SSL_shutdown(ssl);
				SSL_free(ssl);
				close(sock);
				return 0;
			}
			else
			{ // The parent process
				close(sock);
			}
		}
		return 0;
	}
}

int setupTCPServer()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(4433);
	int err = bind(listen_sock, (struct sockaddr *)&sa_server, sizeof(sa_server));
	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
}
