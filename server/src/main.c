#include "common.h"
#include "network.h"
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
		fprintf(stderr,"error!this server must be run as root\n");
		return 1;
	}

	//deal with signal
	signal(SIGINT,stop_handler);
	signal(SIGTERM,stop_handler);
	signal(SIGPIPE,stop_handler);
	signal(26,ignore_handler);

	//create socket
	//int sockfd =
	return 0;
}
