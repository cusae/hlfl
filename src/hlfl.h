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

void read_file(FILE *, char *);
int icmp(char *);

#endif				/* __HLFL_H__ */
