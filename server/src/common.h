#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAXSIZE		1024
#define MIDSIZE		256
#define SMALLSIZE	64
#define MINSIZE		16

#define SUCCESS		0
#define FAILED		-1

#define SERVERIP	"127.0.0.1"
#define SERVERPORT	24444
#define MAX_SOCKET_CONN 20
#define CACERT		"/usr/share/server/cacert.pem"
#define SERVER_CERT	"/usr/share/server/sslservercert.pem"
#define SERVER_PRIVATE_KEY "/usr/share/server/sslserverkey.pem"

#ifndef likely
#define likely(x)   __builtin_expect(!!(x) , 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x) , 0)
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#endif
