#ifndef __HLFL_INCLUDES__
#include "config.h"
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif


#define ACCEPT_ONE_WAY 1			/*  ->           */
#define ACCEPT_ONE_WAY_REVERSE 2		/* <-            */
#define ACCEPT_TWO_WAYS 3 			/* <->           */
#define ACCEPT_TWO_WAYS_ESTABLISHED 4 		/* <=>> 	 */
#define ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE 11  /* <<=>		 */
#define DENY 5					/*  X            */
#define DENY_LOG 12				/*  Xl		 */
#define REJECT 6				/*  X!           */
#define DENY_OUT 7				/* X->           */
#define DENY_IN 8				/* <-X           */
#define REJECT_OUT 9				/* X!->          */
#define REJECT_IN 10				/* <-X!          */

#define COMMENT 1
#define INCLUDE_TEXT 2
#endif
