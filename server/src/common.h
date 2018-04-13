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
#define FAILED		1

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
