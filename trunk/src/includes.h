#ifndef __HLFL_INCLUDES__
#define __HLFL_INCLUDES__

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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
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

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define ACCEPT	 		1
#define DENY     		2
#define REJECT   		4
#define ONE_WAY  		8
#define ONE_WAY_REVERSE 	16
#define ESTABLISHED 		32
#define TWO_WAYS 		ONE_WAY|ONE_WAY_REVERSE
#define LOG			64

#define ACCEPT_ONE_WAY 				(ACCEPT|ONE_WAY)	/*  ->           */
#define ACCEPT_ONE_WAY_REVERSE 			(ACCEPT|ONE_WAY_REVERSE)	/* <-            */
#define ACCEPT_TWO_WAYS 			(ACCEPT|TWO_WAYS)	/* <->           */
#define ACCEPT_TWO_WAYS_ESTABLISHED 		(ACCEPT|ONE_WAY|ESTABLISHED)	/* <=>>          */
#define ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE 	(ACCEPT|ONE_WAY_REVERSE|ESTABLISHED)	/* <<=>          */
#define DENY_ALL 				(DENY|TWO_WAYS)	/*  X            */
#define REJECT_ALL 				(REJECT|TWO_WAYS)	/*  X!           */
#define DENY_OUT 				(DENY|ONE_WAY)	/* X->           */
#define DENY_IN 				(DENY|ONE_WAY_REVERSE)	/* <-X           */
#define REJECT_OUT 				(REJECT|ONE_WAY)	/* X!->          */
#define REJECT_IN 				(REJECT|ONE_WAY_REVERSE)	/* <-X!          */

#define COMMENT 1
#define INCLUDE_TEXT 2

#endif				/* __HLFL_INCLUDES__ */
