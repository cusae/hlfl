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
#include "hlfl.h"
#include "linux_ipchains.h"


extern int matched_if;

/*------------------------------------------------------------------
 * Private functions
 *------------------------------------------------------------------*/


static char *
icmp_types(type)
 char *type;
{
 char *ret = malloc(40 + strlen(type));
 bzero(ret, 40 + strlen(type));
 if (!strlen(type))
  return ret;

 if (!strcmp(type, "echo-reply") ||
     !strcmp(type, "destination-unreachable") ||
     !strcmp(type, "echo-request") || !strcmp(type, "time-exceeded"))
  sprintf(ret, "--icmp-type %s", type);
 else
  fprintf(stderr, "Warning. Unknown icmp type '%s'\n", type);
 return ret;
}




/*------------------------------------------------------------------
 * Linux ipchains
 *------------------------------------------------------------------*/
int
translate_linux_ipchains(op, proto, src, log, dst, sports, dports, interface)
 int op;
 char *proto;
 char *src;
 int log;
 char *dst;
 char *sports;
 char *dports;
 char *interface;
{
 char *via = strdup("");
 char *t;
 char *icmp_code = NULL;
 char *logit = "";

 if (log)
  logit = " -l";

 if (icmp(proto))
   {
    if (sports && strlen(sports))
     icmp_code = icmp_types(sports);
    else if (dports && strlen(dports))
     icmp_code = icmp_types(dports);
    else
     icmp_code = icmp_types("");

    dports = icmp_code;
    sports = "";
   }
 else
   {
    if (sports)
     while ((t = strchr(sports, '-')))
      t[0] = ':';
    if (dports)
     while ((t = strchr(dports, '-')))
      t[0] = ':';
   }


 if (interface)
   {
    free(via);
    via = malloc(10 + strlen(interface));
    sprintf(via, "-i %s", interface);
   }
 switch (op)
   {
   case ACCEPT_ONE_WAY:
    printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	   logit, src, sports, dst, dports, proto, via);
    break;
   case ACCEPT_ONE_WAY_REVERSE:
    printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n", logit,
	   dst, dports, src, sports, proto, via);
    break;
   case ACCEPT_TWO_WAYS:
    printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	   logit, src, sports, dst, dports, proto, via);
    printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n", logit,
	   dst, dports, src, sports, proto, via);
    break;
   case ACCEPT_TWO_WAYS_ESTABLISHED:
    if (!strcmp(proto, "tcp"))
      {
       printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, src, sports, dst, dports, proto, via);
       printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -y -j DENY %s\n",
	      logit, dst, dports, src, sports, proto, via);
       printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, dst, dports, src, sports, proto, via);
      }
    else
      {
       /* XXX stateful needed here */
       printf("# (warning. A stateful firewall would be better here)\n");
       printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, src, sports, dst, dports, proto, via);
       printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, dst, dports, src, sports, proto, via);
      }
    break;
   case ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE:
    if (!strcmp(proto, "tcp"))
      {
       printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, dst, dports, src, sports, proto, via);
       printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -y -j DENY %s\n",
	      logit, src, sports, dst, dports, proto, via);
       printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, src, sports, dst, dports, proto, via);
      }
    else
      {
       /* XXX stateful needed here */
       printf("# (warning. A stateful firewall would be better here)\n");
       printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, dst, dports, src, sports, proto, via);
       printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j ACCEPT %s\n",
	      logit, src, sports, dst, dports, proto, via);
      }
    break;
   case DENY:
    printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j DENY %s\n", logit,
	   src, sports, dst, dports, proto, via);
    printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j DENY %s\n", logit,
	   dst, dports, src, sports, proto, via);
    break;
   case REJECT:
    printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j REJECT %s\n",
	   logit, src, sports, dst, dports, proto, via);
    printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j REJECT %s\n", logit,
	   dst, dports, src, sports, proto, via);
    break;
   case DENY_OUT:
    printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j DENY %s\n", logit,
	   src, sports, dst, dports, proto, via);
    break;
   case DENY_IN:
    printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j DENY %s\n", logit,
	   dst, dports, src, sports, proto, via);
    break;
   case REJECT_OUT:
    printf("$ipchains -A output%s -s %s %s -d %s %s -p %s -j REJECT %s\n",
	   logit, src, sports, dst, dports, proto, via);
    break;
   case REJECT_IN:
    printf("$ipchains -A input%s -s %s %s -d %s %s -p %s -j REJECT %s\n", logit,
	   dst, dports, src, sports, proto, via);
    break;
   }
 free(via);
 if (icmp_code)
  free(icmp_code);
 return 0;
}



int
translate_linux_ipchains_start()
{
 printf("#!/bin/sh\n");
 printf("# Firewall rules generated by hlfl\n\n");

 printf("ipchains=\"/sbin/ipchains\"\n\n");
 printf("$ipchains -F\n");
 printf("$ipchains -X\n");
 printf("$ipchains -P input DENY\n");
 printf("$ipchains -P forward DENY\n");
 printf("$ipchains -P output DENY\n");
 return 0;
}

void
include_text_ipchains(c)
 char *c;
{
 if (!strncmp("if(", c, 3))
   {
    if (!strncmp("if(ipchains)", c, strlen("if(ipchains)")))
     {
      printf("%s", c + strlen("if(ipchains)"));
      matched_if = 1;
     }
     else
      matched_if = 0;
   }
 else
  printf("%s", c);
}
