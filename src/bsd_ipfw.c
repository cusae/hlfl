/* hlfl
 * Copyright (C) 2000 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "includes.h"
#include "bsd_ipfw.h"
extern int icmp(char *);

static char *
icmp_types(type)
 char *type;
{
 char *ret = malloc(20);
 bzero(ret, 20);
 if (!strlen(type))
  return ret;
 if (!strcmp(type, "echo-reply"))
  sprintf(ret, "icmptypes 0");
 else if (!strcmp(type, "destination-unreachable"))
  sprintf(ret, "icmptypes 3");
 else if (!strcmp(type, "echo-request"))
  sprintf(ret, "icmptypes 8");
 else if (!strcmp(type, "time-exceeded"))
  sprintf(ret, "icmptypes 11");
 else
  fprintf(stderr, "Warning. Unknown icmp type '%s'\n", type);
 return ret;
}

/*------------------------------------------------------------------
 * BSD's ipfw
 *------------------------------------------------------------------*/
int
translate_bsd_ipfw(op, proto, src, dst, sports, dports, interface)
 int op;
 char *proto;
 char *src;
 char *dst;
 char *sports;
 char *dports;
 char *interface;
{
 char *via = strdup("");
 char *icmp_code = "";

 if (icmp(proto))
   {
    if (sports && strlen(sports))
     icmp_code = icmp_types(sports);
    else if (dports && strlen(dports))
     icmp_code = icmp_types(dports);
    else
     icmp_code = icmp_types("");

    sports = "";
    dports = "";
   }


 if (!sports)
  sports = "";
 if (!dports)
  dports = "";

 if (interface)
   {
    free(via);
    via = malloc(10 + strlen(interface));
    sprintf(via, "via %s", interface);
   }
 switch (op)
   {
   case ACCEPT_ONE_WAY:
    printf("$ipfw -f add allow %s from %s %s to %s %s out %s %s\n", proto, src,
	   sports, dst, dports, icmp_code, via);
    break;
   case ACCEPT_ONE_WAY_REVERSE:
    printf("$ipfw -f add allow %s from %s %s to %s %s in %s %s\n", proto, dst,
	   dports, src, sports, icmp_code, via);
    break;
   case ACCEPT_TWO_WAYS:
    printf("$ipfw -f add allow %s from %s %s to %s %s out %s %s\n", proto, src,
	   sports, dst, dports, icmp_code, via);
    printf("$ipfw -f add allow %s from %s %s to %s %s in %s %s\n", proto, dst,
	   dports, src, sports, icmp_code, via);
    break;
   case ACCEPT_TWO_WAYS_ESTABLISHED:
    if (!strcmp(proto, "tcp"))
      {
       printf("$ipfw -f add allow %s from %s %s to %s %s out %s\n", proto, src,
	      sports, dst, dports, via);
       printf("$ipfw -f add deny %s from %s %s to %s %s in setup %s\n", proto,
	      dst, dports, src, sports, via);
       printf("$ipfw -f add accept %s from %s %s to %s %s in %s\n", proto, dst,
	      dports, src, sports, via);
      }
    else
      {
       /* XXX stateful needed here */
       printf("# (warning. A stateful firewall would be better here)\n");
       printf("$ipfw -f add allow %s from %s %s to %s %s out %s %s\n", proto,
	      src, sports, dst, dports, icmp_code, via);
       printf("$ipfw -f add allow %s from %s %s to %s %s in %s %s\n", proto,
	      dst, dports, src, sports, icmp_code, via);
      }
    break;

   case ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE:
    if (!strcmp(proto, "tcp"))
      {
       printf("$ipfw -f add allow %s from %s %s to %s %s in %s\n", proto, dst,
	      dports, src, sports, via);
       printf("$ipfw -f add deny %s from %s %s to %s %s out setup %s\n", proto,
	      src, sports, dst, dports, via);
       printf("$ipfw -f add accept %s from %s %s to %s %s out %s\n", proto, src,
	      sports, dst, dports, via);
      }
    else
      {
       /* XXX stateful needed here */
       printf("# (warning. A stateful firewall would be better here)\n");
       printf("$ipfw -f add allow %s from %s %s to %s %s in %s %s\n", proto,
	      dst, dports, src, sports, icmp_code, via);
       printf("$ipfw -f add allow %s from %s %s to %s %s out %s %s\n", proto,
	      src, sports, dst, dports, icmp_code, via);
      }
    break;
   case DENY:
    printf("$ipfw -f add deny %s from %s %s to %s %s out %s %s\n", proto, src,
	   sports, dst, dports, icmp_code, via);
    printf("$ipfw -f add deny %s from %s %s to %s %s in %s %s\n", proto, dst,
	   dports, src, sports, icmp_code, via);
    break;
   case DENY_LOG:
    printf("$ipfw -f add deny log %s from %s %s to %s %s out %s %s\n", proto,
	   src, sports, dst, dports, icmp_code, via);
    printf("$ipfw -f add deny log %s from %s %s to %s %s out %s %s\n", proto,
	   src, sports, dst, dports, icmp_code, via);
    break;
   case REJECT:
    printf("$ipfw -f add reject %s from %s %s to %s %s out %s %s\n", proto, src,
	   sports, dst, dports, icmp_code, via);
    printf("$ipfw -f add reject %s from %s %s to %s %s in %s %s\n", proto, dst,
	   dports, src, sports, icmp_code, via);
    break;
   case DENY_OUT:
    printf("$ipfw -f add deny %s from %s %s to %s %s out %s %s\n", proto, src,
	   sports, dst, dports, icmp_code, via);
    break;
   case DENY_IN:
    printf("$ipfw -f add deny %s from %s %s to %s %s in %s %s\n", proto, dst,
	   dports, src, sports, icmp_code, via);
    break;
   case REJECT_OUT:
    printf("$ipfw -f add reject %s from %s %s to %s %s out %s %s\n", proto, src,
	   sports, dst, dports, icmp_code, via);
    break;
   case REJECT_IN:
    printf("$ipfw -f add reject %s from %s %s to %s %s in %s %s\n", proto, dst,
	   dports, src, sports, icmp_code, via);
    break;
   }
 free(via);
 if (icmp(proto))
   {
    free(icmp_code);
   }
 return 0;
}


int
translate_bsd_ipfw_start()
{
 printf("#!/bin/sh\n#\n");
 printf("# Firewall rules generated by hlfl\n\n");

 printf("ipfw=\"/sbin/ipfw -q\"\n\n");
 printf("$ipfw -f flush\n\n");
 return 0;
}

void
include_text_ipfw(c)
 char *c;
{
 if (!strncmp("if(", c, 3))
   {
    if (!strncmp("if(ipfw)", c, strlen("if(ipfw)")))
     printf("%s", c + strlen("if(ipfw)"));
   }
 else
  printf("%s", c);
}