#ifndef _GNU_SOURCE 
#define _GNU_SOURCE
#endif

#include "network.h"
#include <errno.h>

int set_nonblock(int fd , int flag)
{
    int prev    = fcntl(fd , F_GETFL);
	if (prev < 0)
	    return errno;
	if (flag)
		return fcntl(fd , F_SETFL , prev | O_NONBLOCK);
	else
	return fcntl(fd , F_SETFL , prev & ~O_NONBLOCK);

}

int create_socket(const char* ip , int port , int domain , int type , int proto , int backlog , int nonblock)
{
	if (!ip)
		return FAILED;
	if (!domain)
	    domain  = AF_INET;
	if (!type)
	    type    = SOCK_STREAM | SOCK_CLOEXEC;
	if (!proto)
	    proto   = IPPROTO_TCP;
	if (!backlog)
	    backlog = 20;
	int sock_fd = socket(domain , type , proto);
	if (sock_fd < 0)
	    return FAILED;
	Set_NonBlock(sock_fd , nonblock);

	struct sockaddr_in stSockAddr;
	memset(&stSockAddr , 0 , sizeof(struct sockaddr_in));

	stSockAddr.sin_family   = domain;
	stSockAddr.sin_addr.s_addr  = inet_addr(ip);
	stSockAddr.sin_port = htons(port);

	if (bind(sock_fd , (struct sockaddr *)&stSockAddr , sizeof(struct sockaddr_in)) == -1)
	{
        close(sock_fd);
        return FAILED;
	}

	if (listen(sock_fd , backlog) == -1)
	{
	    close(sock_fd);
	    return FAILED;
	}

	return sock_fd;

}

void close_socket(int fd)
{
	shutdown(fd , SHUT_RDWR);
	close(fd);
}

Channel* channel_new()
{
	Channel* result = (Channel*)malloc(sizeof(Channel));
	if (unlikely(!result))
	{
		printf("[%s:%d]alloc failed：%s" , __FUNCTION__ , __LINE__ , strerror(errno));
		return NULL;
	}   
	else
		memset(result , 0 , sizeof(Channel));
	return result;
}

void free_channel(Channel* ch) 
{
	if (ch->fd > -1) 
	{
		close_socket(ch->fd);
		ch->fd  = -1; 
		ch->tcpConnected = 0;
	}
	if (ch->ssl)
	{
		SSL_shutdown(ch->ssl);
		SSL_free(ch->ssl);
		ch->sslConnected = 0;
	}
	free(ch);
	return ;
} 

int set_channelsock(Channel* ch , int fd , int events) 
{
	ch->fd      = fd; 
	ch->events  = events;
	return 0;
}


int accept_connection(int source_fd , Channel* ch)
{
	if (!ch)
	{
		return 1;
	}
	int ret	= 1;
	struct sockaddr_in raddr;
	socklen_t raddr_len	= sizeof(raddr);
	int cfd;
	while ((cfd = accept4(source_fd , (struct sockaddr*)&raddr , &raddr_len , SOCK_CLOEXEC)) >= 0)
	{
		struct sockaddr_in peer;
		socklen_t alen	= sizeof(peer);
		int r	= getpeername(cfd , (struct sockaddr*)&peer , &alen);
		if (unlikely(r < 0))
		{
			continue;
		}
		inet_ntop(AF_INET , &raddr.sin_addr , ch->r_ip , MINSIZE);

		if (unlikely(stEPOLL.curfd >= MAX_EVENTS))
		{
			ret	= 1;
			break;
		}
		Set_NonBlock(cfd , 1);
		Set_ChannelSock(ch , cfd , EPOLLIN | EPOLLOUT);
		printf("[ip:%s]Connection Accepted..\n" , ch->r_ip);
		ret	= 0;
	}
	return ret;
}
