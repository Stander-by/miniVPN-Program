#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client-xr.crt"
#define KEYF	HOME"client-xr.key"
#define CACERT	HOME"ca-xr.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFF_SIZE 4000
int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
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

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

#if 1
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif
	// if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
	// 	ERR_print_errors_fp(stderr);
	// 	exit(-2);
	// }

	// if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
	// 	ERR_print_errors_fp(stderr);
	// 	exit(-3);
	// }

	// if (!SSL_CTX_check_private_key(ctx)) {
	// 	printf("Private key does not match the certificate public keyn");
	// 	exit(-4);
	// }
	if (SSL_CTX_load_verify_locations(ctx, CACERT, NULL) < 1)  {
        printf("Error setting the verify locations. \n");
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
	//server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
	server_addr.sin_port = htons(port);
	server_addr.sin_family = AF_INET;

	// Connect to the destination
	connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));

	return sockfd;
}

int login(SSL *ssl)
{
	char username[20];
	char passwd[20];
	char recvbuf[30];
	memset(username,0,sizeof(username));
	memset(passwd,0,sizeof(passwd));
	memset(recvbuf,0,sizeof(recvbuf));
	printf("username:");
	scanf("%s",username);
	getchar();
	printf("passwd:");
	scanf("%s",passwd);
	getchar();
	SSL_write(ssl,username,strlen(username)+1);
	SSL_write(ssl,passwd,strlen(passwd)+1);
	SSL_read(ssl,recvbuf,sizeof(recvbuf));
	printf("recvbuf:%s\n",recvbuf);
	if(strcmp(recvbuf,"Client verify succeed")){
        printf("Client verify failed!\n");
        return 0;
    }
    printf("client verify succeed!\n");
    return 1;
}

int createTunDevice(int ip) {
    int tunfd;
    struct ifreq ifr;
	char cmd[100];
    memset(&ifr, 0, sizeof(ifr));
	memset(cmd, 0, sizeof(cmd));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
    int ret=ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	int tunId = atoi(ifr.ifr_name+3);
	printf("tunid:%d\n",tunId);

	printf("Setup TUN interface success!\n");
    sprintf(cmd, "sudo ifconfig tun0 192.168.53.%d/24 up && sudo route add -net 192.168.60.0/24 tun0",ip);
    system(cmd);
    return tunfd;
}


int recv_ip(SSL *ssl){
    char buf[BUFF_SIZE];
    SSL_read(ssl,buf,BUFF_SIZE);
    int virtual_ip=atoi(buf);
    printf("virtual ip: 192.168.53.%d/24\n",virtual_ip);
	
    return virtual_ip;
}


int main(int argc, char *argv[])
{
	char *hostname = "yahoo.com";
	int port = 443;

	if (argc > 1)
	hostname = argv[1];
	if (argc > 2)
	port = atoi(argv[2]);

	/*----------------TLS initialization ----------------*/
	SSL *ssl = setupTLSClient(hostname);

	/*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);

	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);

	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*----------------Send/Receive data --------------------*/


	
	if(!login(ssl)){
		SSL_shutdown(ssl);
        SSL_free(ssl);
		close(sockfd);
        return 0;
	}
	int ip = recv_ip(ssl);
	
	int tunfd = createTunDevice(ip);
	char buf[BUFF_SIZE];
	
	int len;

	while(1){
		fd_set read_fd;
		FD_ZERO(&read_fd);
		FD_SET(sockfd,&read_fd);
		FD_SET(tunfd,&read_fd);
		select(FD_SETSIZE,&read_fd,NULL,NULL,NULL);
		if(FD_ISSET(tunfd,&read_fd)){
			printf("Got a packet from TUN\n");
			bzero(buf, BUFF_SIZE);
			len = read(tunfd,buf,BUFF_SIZE);
			
			buf[len] = '\0';
			SSL_write(ssl,buf,len);
		}
		
		if(FD_ISSET(sockfd,&read_fd)){
			printf("Got a packet from the tunnel\n");
			bzero(buf, BUFF_SIZE);
			len = SSL_read(ssl,buf,BUFF_SIZE);
			
			if(len==0){
				fprintf(stderr,"the ssl socket close!\n");
				return;
			}
			buf[len]='\0';
		 	write(tunfd,buf,len);
		}
		
	}

	SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
	return 0;
	// int len;

	// do {
	// 	len = SSL_read(ssl, buf, sizeof(buf) - 1);
	// 	buf[len] = '\0';
	// 	printf("%s\n", buf);
	// } while (len > 0);
}

