#include "ssl.h"
#include "network.h"

int Verify_Callback_Server(int ok , X509_STORE_CTX* pstCtx)
{
	return ok;
}

int SSL_CTX_use_PrivateKey_file_pass(SSL_CTX* pstCtx , char* filename , char* pwd)
{
	EVP_PKEY *pkey = NULL;
	BIO *key = NULL;

	key = BIO_new(BIO_s_file());
	BIO_read_filename(key, filename);
	pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, pwd);
	if (pkey == NULL)
	{
		printf("PEM_read_bio_PrivateKey err , errno %d" , errno);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey(pstCtx, pkey) <= 0)
	{
		printf("SSL_CTX_use_PrivateKey err");
		return -1;
	}
	BIO_free(key);
	return 1;
}

int init_ssl()
{
	int retv	= 0;
	SSL_load_error_strings();
	SSL_library_init();
	SSLeay_add_ssl_algorithms();
	pstCtx	= SSL_CTX_new(TLSv1_server_method());
	if (!pstCtx)
	{
		ERR_print_errors_fp(stderr);
		retv	= -1;
		goto clean_up;
	}

	s_server_verify	= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE;
	SSL_CTX_set_verify(pstCtx , s_server_verify , Verify_Callback_Server);

	if ((!SSL_CTX_load_verify_locations(pstCtx , CACERT , NULL)) || (!SSL_CTX_set_default_verify_paths(pstCtx)))
	{
		printf("SSL_CTX_load_verify_locations error\n");
		retv	= -2;
		goto clean_up;
	}

	if (SSL_CTX_use_certificate_file(pstCtx , SERVER_CERT , SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		retv	= -3;
		goto clean_up;
	}

	if (SSL_CTX_use_PrivateKey_file_pass(pstCtx , SERVER_PRIVATE_KEY , PRIVATE_KEY_PWD) <= 0)
	{
		ERR_print_errors_fp(stderr);
		retv	= -4;
		goto clean_up;
	}

	if (!SSL_CTX_check_private_key(pstCtx))
	{
		printf("Private key does not match the certificate public key\n");
		retv	= -5;
		goto clean_up;
	}

clean_up:
	return retv;
}


int SSL_Verify_Client_Cert(SSL* ssl)
{
	int retv	= 0;
	X509* pstClientCert	= NULL;
	char* pcStr	= NULL;
	pstClientCert	= SSL_get_peer_certificate(ssl);
	if (pstClientCert)
	{
		int ret	= SSL_get_verify_result(ssl);
		if (ret != X509_V_OK)
		{
			retv	= 1;
			goto clean_up;
		}
		pcStr	= X509_NAME_oneline(X509_get_subject_name(pstClientCert), 0, 0);
		if (!pcStr)
		{
			retv	= 1;
			goto clean_up;
		}
/*
		char *CertStatusReq[16]	= {"-issuer" , CACERT , "-CAfile" , CACERT , "-cert" , (char*)pstClientCert , "-url" , CAHOST};
		if (SSL_CheckCertStatus(CertStatusReq) == V_OCSP_GERTSTATUS_GOOD)
		{
			retv	= 0;
			printf("SSL cert is valid\n");
			goto clean_up;
		}
		else
		{
			printf("SSL cert is not valid\n");
			retv	= 2;
			goto clean_up;
		}
*/
	}
	else
	{
		printf("[%s:%d]cannot get client cert\n" , __FUNCTION__ , __LINE__);
		retv	= 1;
	}

clean_up:
	if (pstClientCert)
	{
		X509_free(pstClientCert);
		pstClientCert	= NULL;
	}
	if (pcStr)
	{
		free(pcStr);
		pcStr	= NULL;
	}

	return retv;
}
/*
int Write_Msg(SSL* ssl , const void* buffer , int bufSize)
{

	int retv		= 1;

	struct itimerval itv;
	itv.it_interval.tv_sec	= 0;
	itv.it_interval.tv_usec	= 0;
	itv.it_value.tv_sec	= 2;			//这里设置两秒，实际上在代码逻辑中只会让其运行一秒
	itv.it_value.tv_usec	= 0;

	int timer		= 0;
	int send_ret		= 0;
	if ((send_ret = SSL_write(ssl , buffer , bufSize)) < 0)
	{
		int err		= SSL_get_error(ssl , send_ret);
		if (err == SSL_ERROR_WANT_WRITE)
		{
			setitimer(ITIMER_VIRTUAL , &itv , NULL);
			while(getitimer(ITIMER_VIRTUAL , &itv ) == 0)
			{
				if(itv.it_value.tv_sec != 0)			
				{
					send_ret	= SSL_write(ssl , buffer , bufSize);
					timer ++;
					if (send_ret == bufSize)
					{
						retv	= 0;
						itv.it_value.tv_sec	= 0;
						itv.it_value.tv_usec	= 0;
						setitimer(ITIMER_VIRTUAL , &itv , NULL);
						goto clean_up;
					}
				}
				else
				{
					retv	= 1;
					goto clean_up;
				}
			}
			retv	= 2;
			goto clean_up;
		}
		else
		{
			retv	= 3;
			goto clean_up;
		}
	}
	else
		retv	= 0;

clean_up:
	return retv;
}

int Read_Msg(SSL* ssl , char* buffer , int bufSize)
{
	int retv	= 1;
	char read_buffer[bufSize];
	memset(read_buffer , 0 , bufSize);
	int read_ret	= SSL_read(ssl , &read_buffer , bufSize);
	if (read_ret == 0)
	{
		retv	= 1;
	}
	else if (read_ret < 0)
	{
		int errcode	= SSL_get_error(ssl , read_ret);
		printf("SSL_read errcode %d , err msg %s\n" , errcode , strerror(errno));
		retv	= -1;
	}
	else
	{
		retv	= 0;
		memcpy(buffer , read_buffer , bufSize);
	}

	return retv;
}
*/

void close_ssl()
{
	printf("call %s\n",__FUNCTION__);
	if (pstCtx)
		SSL_CTX_free(pstCtx);
	ERR_free_strings();
	printf("%s done\n",__FUNCTION__);
}
