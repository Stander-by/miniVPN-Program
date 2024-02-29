#include <arpa/inet.h>
#include <crypt.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <shadow.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
/* define HOME to be dir for key and cert files... */
#define HOME	"./cert/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server-xr.crt"
#define KEYF	HOME"server-xr.key"
#define CACERT	HOME"ca-xr.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFFER_SIZE 4000
pthread_mutex_t mutex;


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
	return preverify_ok;
}
typedef struct pipe_data {
    char *pipe_file;
    SSL *ssl;
} PIPEDATA;

int setupTCPServer();	// Defined in Listing 19.10
void processRequest(SSL * ssl, int sock);	// Defined in Listing 19.12
void *listen_tun(void *tunfd);
int createTunDevice();
int login(SSL *ssl);
int send_ip(SSL* ssl,int virtual_ip);
void *listen_pipe(void *threadData) ;

int main()
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	int err;

	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

#if 0
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
	// Step 3: Create a new SSL structure for a connection
	ssl = SSL_new(ctx);

	struct sockaddr_in sa_client;
	size_t client_len = sizeof(sa_client);
	int listen_sock = setupTCPServer();
	int pipe_id=0;
	fprintf(stderr, "listen_sock = %d\n", listen_sock);
	int tunfd = createTunDevice();
	system("rm -rf pipe");
    mkdir("pipe", 0666);
	pthread_t listen_tun_thread;
    pthread_create(&listen_tun_thread, NULL, listen_tun, (void *)&tunfd);
	while (1) {
		int sock = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);
		++pipe_id;
		
		if(sock==-1){
			fprintf(stderr,"error accept client!\n");
			return -1;
		}
		fprintf(stderr, "sock = %d\n", sock);
		if (sock == -1) {
			fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			continue;
		}
		if (fork() == 0) {	// The child process
			
			//close(listen_sock);

			SSL_set_fd(ssl, sock);
			int err = SSL_accept(ssl);

			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");
			if(login(ssl)){
				char pipe_file[20];
				
				memset(pipe_file,0,sizeof(pipe_file));
                sprintf(pipe_file, "./pipe/myfifo%d", (int)pipe_id);
				send_ip(ssl,pipe_id+5);
				
				if(mkfifo(pipe_file,0666)!=-1){
					pthread_t listen_pipe_thread;
                    PIPEDATA pipeData;
                    pipeData.pipe_file = pipe_file;
                    pipeData.ssl = ssl;
                    pthread_create(&listen_pipe_thread, NULL, listen_pipe, (void *)&pipeData);
					char buf[BUFFER_SIZE];
					int len;
					
					while(1){
						memset(buf,0,sizeof(buf));
						len = SSL_read(ssl,buf,BUFFER_SIZE);
						if(len==0){
							fprintf(stderr,"the ssl socket close!\n");
							return;
						}
						buf[len]='\0';
						write(tunfd,buf,len);
						
					}
					pthread_cancel(listen_pipe_thread);
				}
				else{
					printf("Warning\n");
				}
				printf("close\n");
				
			}
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sock);
			printf(" Socket closed!\n");
			return 0;
		}
	    else {	// The parent process
			//close(sock);
		}	
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
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
}



void *listen_tun(void *tunfd) 
{
	
    int fd = *((int *)tunfd);
    char buff[2000];
    while (1) {
        int len = read(fd, buff, 2000);
		
        if (len > 19 && buff[0] == 0x45) {
            printf("TUN Received, length : %d , destination : 192.168.53.%d\n", len, (int)buff[19]);
            const char pipe_file[20];
            sprintf(pipe_file, "./pipe/myfifo%d", (int)(buff[19]-5));
			
            int fd = open(pipe_file, O_WRONLY);
			
            if (fd == -1) {
                printf("[WARNING] File %s does not exist.\n", pipe_file);
            } else {
                write(fd, buff, len);
            }
			
        }
    }
}

int login(SSL *ssl)
{
	char username[20], passwd[20];
	memset(username,0,sizeof(username));
	memset(passwd,0,sizeof(passwd));
	SSL_read(ssl, username, sizeof(username) - 1);
	printf("Received: %s\n", username);
	SSL_read(ssl, passwd, sizeof(passwd) - 1);
	printf("Received: %s\n", passwd);
	struct spwd *pw;
    char *epasswd; 
    pw = getspnam(username);
    if (pw == NULL) {
        printf("Error: Password is NULL.\n");
        return 0;
    }

    printf("USERNAME : %s\n", pw->sp_namp);
    printf("PASSWORD : %s\n", pw->sp_pwdp);

    epasswd = crypt(passwd, pw->sp_pwdp);
	
    if (strcmp(epasswd, pw->sp_pwdp)) {
		char no[] = "Client verify failed";
		printf("%s\n",no);
        SSL_write(ssl, no, strlen(no)+1);
        printf("Error: The password is incorrect!\n");
        return 0;
    }
	char yes[] = "Client verify succeed";
    printf("%s\n",yes);
    SSL_write(ssl, yes, strlen(yes));
    return 1;
}

int createTunDevice() 
{
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);

	system("sudo ifconfig tun0 192.168.53.1/24 up && sudo sysctl net.ipv4.ip_forward=1");
	
    return tunfd;
}

int send_ip(SSL* ssl,int virtual_ip)
{
	char buf[10];
    sprintf(buf,"%d",virtual_ip);
    printf("send virtual IP: 192.168.53.%s/24\n",buf);
    SSL_write(ssl,buf,strlen(buf)+1);
}

void *listen_pipe(void *threadData) {
    PIPEDATA *ptd = (PIPEDATA*)threadData;
    int pipefd = open(ptd->pipe_file, O_RDONLY);

    char buff[2000];
    int len;
    do {
        len = read(pipefd, buff, 2000);
        SSL_write(ptd->ssl, buff, len);
    } while (len > 0);
    printf("%s read 0 byte. Connection closed and file removed.\n", ptd->pipe_file);
    remove(ptd->pipe_file);
}
