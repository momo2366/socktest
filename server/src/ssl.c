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
	int ret	= 0;
	SSL_load_error_strings();
	SSL_library_init();
	SSLeay_add_ssl_algorithms();
	pstCtx	= SSL_CTX_new(TLSv1_server_method());
	if (!pstCtx)
	{
		ERR_print_errors_fp(stderr);
		ret	= -1;
		return ret;
	}

	s_server_verify	= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE;
	SSL_CTX_set_verify(pstCtx , s_server_verify , Verify_Callback_Server);

	if ((!SSL_CTX_load_verify_locations(pstCtx , CACERT , NULL)) || (!SSL_CTX_set_default_verify_paths(pstCtx)))
	{
		printf("SSL_CTX_load_verify_locations error\n");
		ret	= -2;
		return ret;
	}

	if (SSL_CTX_use_certificate_file(pstCtx , SERVER_CERT , SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		ret	= -3;
		return ret;
	}

	if (SSL_CTX_use_PrivateKey_file_pass(pstCtx , SERVER_PRIVATE_KEY , PRIVATE_KEY_PWD) <= 0)
	{
		ERR_print_errors_fp(stderr);
		ret	= -4;
		return ret;
	}

	if (!SSL_CTX_check_private_key(pstCtx))
	{
		printf("Private key does not match the certificate public key\n");
		ret	= -5;
		return ret;
	}

clean_up:
	return ret;
}


int SSL_Verify_Client_Cert(SSL* ssl)
{
	int ret	= 0;
	X509* pstClientCert	= NULL;
	char* pcStr	= NULL;
	pstClientCert	= SSL_get_peer_certificate(ssl);
	if (pstClientCert)
	{
		int ret	= SSL_get_verify_result(ssl);
		if (ret != X509_V_OK)
		{
			ret	= 1;
			return ret;
		}
		pcStr	= X509_NAME_oneline(X509_get_subject_name(pstClientCert), 0, 0);
		if (!pcStr)
		{
			ret	= 1;
			return ret;
		}
/*
		char *CertStatusReq[16]	= {"-issuer" , CACERT , "-CAfile" , CACERT , "-cert" , (char*)pstClientCert , "-url" , CAHOST};
		if (SSL_CheckCertStatus(CertStatusReq) == V_OCSP_GERTSTATUS_GOOD)
		{
			ret	= 0;
			printf("SSL cert is valid\n");
			return ret;
		}
		else
		{
			printf("SSL cert is not valid\n");
			ret	= 2;
			return ret;
		}
*/
	}
	else
	{
		printf("[%s:%d]cannot get client cert\n" , __FUNCTION__ , __LINE__);
		ret	= 1;
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

	return ret;
}
int write_msg(SSL* ssl , const void* buffer , int bufSize)
{

	int ret		= 1;

	struct itimerval itv;
	itv.it_interval.tv_sec	= 0;
	itv.it_interval.tv_usec	= 0;
	itv.it_value.tv_sec	= 2;
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
						ret	= 0;
						itv.it_value.tv_sec	= 0;
						itv.it_value.tv_usec	= 0;
						setitimer(ITIMER_VIRTUAL , &itv , NULL);
						return ret;
					}
				}
				else
				{
					ret	= 1;
					return ret;
				}
			}
			ret	= 2;
			return ret;
		}
		else
		{
			ret	= 3;
			return ret;
		}
	}
	else
		ret	= 0;

	return ret;
}

int read_msg(SSL* ssl , char* buffer , int bufSize)
{
	int ret	= 1;
	char read_buffer[bufSize];
	memset(read_buffer , 0 , bufSize);
	int read_ret	= SSL_read(ssl , &read_buffer , bufSize);
	if (read_ret == 0)
	{
		ret	= 1;
	}
	else if (read_ret < 0)
	{
		int errcode	= SSL_get_error(ssl , read_ret);
		printf("SSL_read errcode %d , err msg %s\n" , errcode , strerror(errno));
		ret	= -1;
	}
	else
	{
		ret	= 0;
		memcpy(buffer , read_buffer , bufSize);
	}

	return ret;
}

void close_ssl()
{
	printf("call %s\n",__FUNCTION__);
	if (pstCtx)
		SSL_CTX_free(pstCtx);
	ERR_free_strings();
	printf("%s done\n",__FUNCTION__);
}

int ssl_handshake(Channel* ch)
{
	int ret	= 0;
	if (!ch->tcpConnected)
	{
		struct epoll_event tmp_event;
		int r	= epoll_wait(stEPOLL.epollfd , &tmp_event , 1 , 0);
		if (r == 1 && tmp_event.events & EPOLLOUT)
		{
			ch->tcpConnected	= 1;
			ch->events		= EPOLLIN | EPOLLOUT | EPOLLERR;
			update_events(ch);
		}
		else
		{
			free_channel(ch);
			ret	= -1;
			return ret;
		}
	}
	
	if (ch->ssl == NULL)
	{
		ch->ssl		= SSL_new(pstCtx);
		if (ch->ssl == NULL)
		{
			printf("[ip:%s]SSL_new Failed\n" , ch->r_ip);
			ret	= -1;
			return ret;
		}
		ret	= SSL_set_fd(ch->ssl , ch->fd);
		if (!ret)
		{
			printf("[ip:%s]SSL_set_fd failed\n" , ch->r_ip);
			ret	= -2;
		}
		SSL_set_accept_state(ch->ssl);
	}

	int hs_ret	= SSL_do_handshake(ch->ssl);
	if (likely(hs_ret == 1))
	{
		if (ca_enable)
		{
			ret	= SSL_Verify_Client_Cert(ch->ssl);
			if (ret)
			{
				ret	= 1;
				printf("[ip:%s]SSL_Verify_Client_Cert failed\n" , ch->r_ip);
				return ret;
			}
		}
		printf("[ip:%s]SSL connected!\n" , ch->r_ip);
		ch->sslConnected	= 1;
		return ret;
	}
	int err	= SSL_get_error(ch->ssl , hs_ret);
	int oldev	= ch->events;
	if (err == SSL_ERROR_WANT_WRITE)
	{
		ch->events	|= EPOLLOUT;
		ch->events	&= ~EPOLLIN;
		printf("[ip:%s]SSL_ERROR_WANT_WRITE\n" , ch->r_ip);
		if (oldev == ch->events)
		{
			ret	= -1;
			return ret;
		}
		Update_Events(ch);
	}
	else if (err == SSL_ERROR_WANT_READ)
	{
		ch->events	|= EPOLLIN;
		ch->events	&= ~EPOLLOUT;
		printf("[ip:%s]SSL_ERROR_WANT_READ\n" , ch->r_ip);
		if (oldev == ch->events)
		{
			ret	= -1;
			return ret;
		}
		Update_Events(ch);
	}
	else
	{
		unsigned long io_err_code	= ERR_get_error();
		const char* const str	= ERR_reason_error_string(io_err_code);
		printf("[ip:%s]SSL handshake failed：%s\n" , ch->r_ip , str);
		Unregister_Events(ch);
		ret	= -1;
	}
	return ret;
}
