#include "common.h"
#include "network.h"
#include "ssl.h"
#include "epoll.h"
#include <sys/types.h>
#include <signal.h>

int sockfd;
int stop = 0;

/*
	close all connections
	free all resources
*/

void free_sources_handler()
{
	close_socket(sockfd);
	close_ssl();
	destroy_events_pool();
	stop = 1;
}

/*
	SIGINT,SIGTERM,SIGPIPE handler 
*/
void stop_handler(int sig)
{
	fprintf(stderr,"server received sig %d to stop",sig);
	free_sources_handler();
}

/*
	SIGVALRM handler
*/
void ignore_handler()
{
	return;
}


int main()
{
	if(geteuid() != 0)
	{
		fprintf(stderr,"error! this server must be run as root\n");
		return FAILED;
	}

	//deal with signal
	signal(SIGINT,stop_handler);
	signal(SIGTERM,stop_handler);
	signal(SIGPIPE,stop_handler);
	signal(26,ignore_handler);

	//create socket
	sockfd = create_socket(SERVERIP,SERVERPORT,AF_INET, SOCK_STREAM | SOCK_CLOEXEC , IPPROTO_TCP , MAX_SOCKET_CONN , 1);
	if(sockfd == FAILED){
		fprintf(stderr,"error! failed to create socket at %s:%d\n",SERVERIP,SERVERPORT);
		free_sources_handler();
		return FAILED;
	}
	printf("start listening %s:%d\n",SERVERIP,SERVERPORT);

	//init ssl
	int sRet = init_ssl();
	if(sRet != 0){
		fprintf(stderr,"error! init_ssl failed! return %d\n",sRet);
		free_sources_handler();
		return FAILED;
	}
	printf("ssl init!\n");

	//create epoll
	if (create_events_pool())
	{
		fprintf(stderr, "cannot create epoll\n");
		free_sources_handler();
		return FAILED;
	}   
	printf("create epoll success\n");
	
	//set channel
	Channel* core   = channel_new();
	if(!core){
		free_sources_handler();
		return FAILED;
	}
	set_channelsock(core , sockfd , EPOLLIN);

	//register event
	if (register_events(core))
	{
		fprintf(stderr,"failed to register event\n");
		free_sources_handler();
		return FAILED;
	}
	printf("register event success\n");

	//start main loop
	while(!stop)
	{
		accept_events(100);
	}

	return SUCCESS;
}
