#ifndef __HLFL_H__
#define __HLFL_H__

#include "bsd_ipfw.h"
#include "cisco.h"
#include "ipfilter.h"
#include "linux_ipchains.h"
#include "linux_ipfwadm.h"
#include "linux_netfilter.h"

#include "errors.h"
#include "getpts.h"
#include "utils.h"

#define MAX_IFACES 40
#define MAX_NETS 1024
#define MAX_PROTOS 4

typedef int (*translator_start_t) (FILE *);
typedef int (*translate_t) (int, char *, char *, int, char *, char *, char *,
			    char *);
typedef void (*comment_t) (char *);
typedef void (*include_text_t) (char *);
typedef void (*exit_t) ();

typedef enum _translator_t
  {
    TRANSLATOR_UNKNOWN = -1,
    TRANSLATOR_IPFW = 0,
    TRANSLATOR_IPFW4 = 1,
    TRANSLATOR_IPFILTER = 2,
    TRANSLATOR_IPFWADM = 3,
    TRANSLATOR_IPCHAINS = 4,
    TRANSLATOR_NETFILTER = 5,
    TRANSLATOR_CISCO = 6,
    TRANSLATOR_MAX = 7
  } translator_t;

typedef struct _translator_definition {
 translator_start_t translator_start;
 translate_t        translate_func;
 comment_t          comment;
 include_text_t     include_text_func;
 exit_t             exit_func;
 } translator_definition;

void nop();
void read_file(FILE *, char *);
int icmp(char *);

#endif				/* __HLFL_H__ */
