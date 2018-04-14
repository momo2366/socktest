#ifndef __EPOLL_H__
#define __EPOLL_H__
#include "sys/epoll.h"
#include "network.h"

#define	MAX_EVENTS	10240

typedef struct{
	int epollfd;
	int curfd;
	int maxfds;
	Channel clients[MAX_EVENTS];
}_stEPOLL;

_stEPOLL	stEPOLL;

extern int	create_events_pool();
extern int	register_events(Channel* ch);
extern int	Update_Events(Channel* ch);
extern int	Unregister_Events(Channel* ch);
extern int	accept_events(int timeout_ms);
extern void	destroy_events_pool();


#endif
