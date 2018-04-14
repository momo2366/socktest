#include "epoll.h"
//#include "../global_schedule.h"
#include <errno.h>

int	Create_Events_Pool();
int	Register_Events(Channel* ch);
int	Update_Events(Channel* ch);
int	Unregister_Events(Channel* ch);
int	Accept_Events(int timeout_ms);
void	Destroy_Events_Pool();

int create_events_pool()
{
	int retv	= 0;
	memset(&stEPOLL , 0 , sizeof(_stEPOLL));
	stEPOLL.epollfd	= epoll_create1(EPOLL_CLOEXEC);
	if (stEPOLL.epollfd <= 0)
	{
		retv	= -1;
		printf("Epoll Create Failed\n");
		goto clean_up;
	}
	
	stEPOLL.curfd	= 0;
	stEPOLL.maxfds	= MAX_EVENTS;

clean_up:	
	return retv;
}

int register_events(Channel* ch)
{
	int retv	= 0;
	if (stEPOLL.curfd + 1 >= stEPOLL.maxfds)
	{
		printf("[ip:%s]Too many connections\n" , ch->r_ip);
		retv	= -1;
		goto clean_up;
	}
	
	struct epoll_event ev;
	memset(&ev , 0 , sizeof(struct epoll_event));
	ev.events	= ch->events;
	ev.data.ptr	= ch;

	retv	= epoll_ctl(stEPOLL.epollfd , EPOLL_CTL_ADD , ch->fd , &ev);
	if (retv)
	{
		printf("[ip:%s]Register Event Failed , errno %d\n" , ch->r_ip , errno);
		goto clean_up;
	}

	stEPOLL.clients[stEPOLL.curfd].fd	= ch->fd;
	stEPOLL.clients[stEPOLL.curfd].events	= ch->events;
	strcpy(stEPOLL.clients[stEPOLL.curfd].r_ip , ch->r_ip);			//warning   貌似不需要保存？？？
	stEPOLL.curfd ++;

clean_up:
	return retv;
}

int Update_Events(Channel* ch)
{
	int retv	= 0;
	struct epoll_event ev;
	memset(&ev , 0 , sizeof(struct epoll_event));
	ev.events	= ch->events;
	ev.data.ptr	= ch;
	retv	= epoll_ctl(stEPOLL.epollfd , EPOLL_CTL_MOD , ch->fd , &ev);
	return retv;
}

int Unregister_Events(Channel* ch)
{
	if (!ch)
		return 1;
	if (ch->fd < 0)
	{
		printf("[ip:%s]channel had been removed\n" , ch->r_ip);
		return 0;
	}
	int retv	= 0;
	struct epoll_event ev;
	memset(&ev , 0 , sizeof(struct epoll_event));
	ev.events	= ch->events;
	ev.data.ptr	= ch;

	retv	= epoll_ctl(stEPOLL.epollfd , EPOLL_CTL_DEL , ch->fd , &ev);
	if (retv < 0)
	{
		printf("[ip:%s]Cannot Unregister Event! errno %d\n" , ch->r_ip , errno);
		goto clean_up;
	}

	stEPOLL.curfd --;
	
clean_up:
	if (ch->fd > -1)
		free_channel(ch);
	return retv;
}

int accept_events(int timeout_ms)
{
	struct epoll_event activeEvs[MAX_EVENTS];
	int counts	= epoll_wait(stEPOLL.epollfd , activeEvs , MAX_EVENTS , timeout_ms);
	if (counts == -1)
	{
		printf("epoll_wait error , error reason : %s\n" , strerror(errno));
		return -1;
	}

	for (int i = 0 ; i < counts ; i ++)
	{
		Channel* ch	= (Channel*)activeEvs[i].data.ptr;
		int events	= activeEvs[i].events;
		printf("fd %d event %d\n" , ch->fd , events);

		if (unlikely(events & EPOLLHUP))				
		{
			printf("[ip:%s]client connecttion lost,remove socket\n" , ch->r_ip);
			if (Unregister_Events(ch))
				printf("[ip:%s]remove socket failed\n" , ch->r_ip);
		}
		else if (events & (EPOLLIN | EPOLLERR))
		{
			//TODO:read func
		}
		else if (events & EPOLLOUT)
		{
			//TODO:write func
		}
		else
		{
			printf("[ip:%s]Unknow Events %d \n" , ch->r_ip , events);
			Unregister_Events(ch);
		}
	}

	return 0;
}


void destroy_events_pool()
{
	if (stEPOLL.epollfd > 0)
		close(stEPOLL.epollfd);
	for (int i = 0 ; i < stEPOLL.curfd ; i ++)
	{
		if (stEPOLL.clients[i].ssl)
		{
			SSL_shutdown(stEPOLL.clients[i].ssl);
			SSL_free(stEPOLL.clients[i].ssl);
			stEPOLL.clients[i].ssl	= NULL;
			stEPOLL.clients[i].sslConnected	= 0;
		}
		if (stEPOLL.clients[i].fd >= 0)
		{
			close_socket(stEPOLL.clients[i].fd);
			stEPOLL.clients[i].fd	= -1;
			stEPOLL.clients[i].tcpConnected	= 0;
		}
	}
}
