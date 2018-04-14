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


int create_socket(const char* ip , int port , int domain , int type , int proto , int backlog , int nonblock);
void    Close_Socket(int fd);
int Set_NonBlock(int fd , int flag);

#endif
