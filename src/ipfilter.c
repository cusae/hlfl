/* hlfl
 * Copyright (C) 2000-2002 Renaud Deraison
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

static FILE *fout;

/*------------------------------------------------------------------
 * Private utilities
 *------------------------------------------------------------------*/

extern int matched_if;

static char *
icmp_types(type)
 char *type;
{
 char *ret = malloc(20);
 memset(ret, 0, 20);
 if (!strlen(type))
  return ret;
 if (!strcmp(type, "echo-reply"))
  sprintf(ret, "icmp-type 0");
 else if (!strcmp(type, "destination-unreachable"))
  sprintf(ret, "icmp-type 3");
 else if (!strcmp(type, "echo-request"))
  sprintf(ret, "icmp-type 8");
 else if (!strcmp(type, "time-exceeded"))
  sprintf(ret, "icmp-type 11");
 else
  fprintf(stderr, "Warning. Unknown icmp type '%s'\n", type);
 return ret;
}

static char *
ipfilter_port(char *port)
{
 char *t;
 if (!port || !strlen(port))
   {
    return strdup("");
   }
 else if ((t = strchr(port, '-')))
   {
    char *ret = malloc(strlen(port) + 20);
    t[0] = '\0';
    if ((atoi(t + 1) + 1) > 65535)
     sprintf(ret, "port %d >< 65535", atoi(port) - 1);
    else
     sprintf(ret, "port %d >< %d", atoi(port) - 1, atoi(t + 1) + 1);
    t[0] = '-';
    return ret;
   }
 else
   {
    char *ret = malloc(strlen(port) + 20);
    sprintf(ret, "port = %s", port);
    return ret;
   }
}

/*------------------------------------------------------------------
 * Darren Reed's ipfilter
 *------------------------------------------------------------------*/
int
translate_ipfilter(op, proto, src, log, dst, sports, dports, interface)
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
 char *p = strdup("");
 char *icmp_code = "";
 char *logit = "";

 if (log)
  logit = " log";

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
 else
   {
    sports = ipfilter_port(sports);
    dports = ipfilter_port(dports);
   }

 if (strcmp(proto, "all"))
   {
    free(p);
    p = malloc(10 + strlen(proto));
    sprintf(p, "proto %s", proto);
   }

 if (interface)
   {
    free(via);
    via = malloc(10 + strlen(interface));
    sprintf(via, "on %s", interface);
   }
 switch (op)
   {
   case ACCEPT_ONE_WAY:
    fprintf(fout, "pass out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   src, sports, dst, dports, icmp_code);
    break;
   case ACCEPT_ONE_WAY_REVERSE:
    fprintf(fout, "pass in%s quick %s %s from %s %s to %s %s %s\n", logit, via, p, dst,
	   dports, src, sports, icmp_code);
    break;
   case ACCEPT_TWO_WAYS:
    fprintf(fout, "pass out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   src, sports, dst, dports, icmp_code);
    fprintf(fout, "pass in%s quick %s %s from %s %s to %s %s %s\n", logit, via, p, dst,
	   dports, src, sports, icmp_code);
    break;
   case ACCEPT_TWO_WAYS_ESTABLISHED:
    if (!strcmp(proto, "tcp") || !strcmp(proto, "udp"))
      {
       fprintf(fout, "pass out%s quick %s %s from %s %s to %s %s keep state\n", logit,
	      via, p, src, sports, dst, dports);
      }
    else
      {
       fprintf(fout, "pass in%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	      dst, dports, src, sports, icmp_code);
       fprintf(fout, "pass out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	      src, sports, dst, dports, icmp_code);
      }
    break;

   case ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE:
    if (!strcmp(proto, "tcp") || !strcmp(proto, "udp"))
      {
       fprintf(fout, "pass in%s quick %s %s from %s %s to %s %s keep state\n", logit,
	      via, p, dst, dports, src, sports);
      }
    else
      {
       fprintf(fout, "pass in%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	      dst, dports, src, sports, icmp_code);
       fprintf(fout, "pass out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	      src, sports, dst, dports, icmp_code);
      }
    break;

   case DENY_ALL:
    fprintf(fout, "block out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   src, sports, dst, dports, icmp_code);
    fprintf(fout, "block in%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   dst, dports, src, sports, icmp_code);
    break;
   case REJECT_ALL:
    if (!strcmp(proto, "tcp"))
     fprintf(fout, "block return-rst in%s quick %s %s from %s %s to %s %s %s\n", logit,
	    via, p, dst, dports, src, sports, icmp_code);
    else
     fprintf(fout, "block return-icmp in%s quick %s %s from %s %s to %s %s %s\n",
	    logit, via, p, dst, dports, src, sports, icmp_code);
    fprintf(fout, "block out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   src, sports, dst, dports, icmp_code);
    break;
   case DENY_OUT:
    fprintf(fout, "block out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   src, sports, dst, dports, icmp_code);
    break;
   case DENY_IN:
    fprintf(fout, "block in%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   dst, dports, src, sports, icmp_code);
    break;
   case REJECT_OUT:
    fprintf(fout, "block out%s quick %s %s from %s %s to %s %s %s\n", logit, via, p,
	   src, sports, dst, dports, icmp_code);
    break;
   case REJECT_IN:
    if (!strcmp(proto, "tcp"))
     fprintf(fout, "block return-rst in%s quick %s %s from %s %s to %s %s %s\n", logit,
	    via, p, dst, dports, src, sports, icmp_code);
    else
     fprintf(fout, "block return-icmp in%s quick %s %s from %s %s to %s %s %s\n",
	    logit, via, p, dst, dports, src, sports, icmp_code);
    break;
   }

 free(via);

 free(p);
 if (icmp(proto))
  free(icmp_code);
 else
   {
    free(sports);
    free(dports);
   }
 return 0;
}

int
translate_ipfilter_start(FILE *output_file)
{
 fout = output_file;

 fprintf(fout, "#\n# ipf(5) rules\n#\n");
 fprintf(fout, "# Firewall rules generated by hlfl\n\n");

 return 0;
}

void
print_comment_ipfilter(buffer)
 char *buffer;
{
 fprintf(fout, buffer);
}

void
include_text_ipfilter(c)
 char *c;
{
 if (!strncmp("if(", c, 3))
   {
    if (!strncmp("if(ipfilter)", c, strlen("if(ipfilter)")))
      {
       fprintf(fout, "%s", c + strlen("if(ipfilter)"));
       matched_if = 1;
      }
    else
     matched_if = 0;
   }
 else
  fprintf(fout, "%s", c);
}
