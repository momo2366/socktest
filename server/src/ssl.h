#ifndef __SSL_H__
#define __SSL_H__

#include "common.h"
#include "openssl/bio.h"
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define	PRIVATE_KEY_PWD		"123123"

SSL_CTX*	pstCtx;
int	s_server_verify;

//int	Read_Msg(SSL* ssl , char* buffer , int bufSize);
//int	Write_Msg(SSL* ssl , const void* buffer , int bufSize);
int	SSL_Verify_Client_Cert(SSL* ssl);
int 	init_ssl();
void	close_ssl();
#endif
