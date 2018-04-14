#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "common.h"
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
//#include "ssl/ssl.h"
#include "fcntl.h"
#include "openssl/bio.h"
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


typedef struct{
	int fd; 
	SSL *ssl;
	int sslConnected;
	int tcpConnected;
	int events;
	char r_ip[MINSIZE];
}Channel;

int create_socket(const char* ip , int port , int domain , int type , int proto , int backlog , int nonblock);
void close_socket(int fd);
int Set_NonBlock(int fd , int flag);
Channel* channel_new();
void free_channel(Channel* ch);
int set_channelsock(Channel* ch , int fd , int events);

#endif
