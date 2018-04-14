#include "common.h"
#include "network.h"
#include "ssl.h"
#include <sys/types.h>
#include <signal.h>

/*
	close all connections
	free all resources
*/

void free_sources_handler()
{
	//ssl_close();
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
	int sockfd = create_socket(SERVERIP,SERVERPORT,AF_INET, SOCK_STREAM | SOCK_CLOEXEC , IPPROTO_TCP , MAX_SOCKET_CONN , 1);
	if(sockfd == FAILED){
		fprintf(stderr,"error! failed to create socket at %s:%d\n",SERVERIP,SERVERPORT);
		return FAILED;
	}
	printf("start listening %s:%d\n",SERVERIP,SERVERPORT);
	//init ssl
	int sRet = init_ssl();

	return SUCCESS;
}
