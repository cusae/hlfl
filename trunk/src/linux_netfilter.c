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
 * Reference : http://netfilter.kernelnotes.org/iptables-HOWTO-7.html
 */

#include "includes.h"
#include "hlfl.h"
#include "linux_netfilter.h"

/*------------------------------------------------------------------
 * Private functions
 *------------------------------------------------------------------*/
 
static char *
icmp_types(type)
 char * type;
{
 char * ret = malloc(40+strlen(type));
 bzero(ret, 40+strlen(type));
 if(!strlen(type))
  return ret;
  
 if(!strcmp(type, "echo-reply") ||
     !strcmp(type, "destination-unreachable")||
     !strcmp(type, "echo-request") ||
     !strcmp(type, "time-exceeded"))
      sprintf(ret, "--icmp-type %s", type);
  else
     fprintf(stderr, "Warning. Unknown icmp type '%s'\n", type);
 return ret;    
}




static char * 
netfilter_sports(ports)
 char * ports;
{
 if(!ports || !strlen(ports))
  return strdup("");
 else
  {
   char * ret = malloc(20 + strlen(ports));
   sprintf(ret, "--source-port %s", ports);
   return ret;
  }
 }

static char * 
netfilter_dports(ports)
 char * ports;
{
 if(!ports || !strlen(ports))
  return strdup("");
 else
  {
   char * ret = malloc(20 + strlen(ports));
   sprintf(ret, "--destination-port %s", ports);
   return ret;
  }
 }
/*------------------------------------------------------------------
 * Linux netfilter
 *------------------------------------------------------------------*/
int
translate_linux_netfilter(op, proto, src, dst, sports, dports, interface)
  int op;
  char * proto;
  char * src;
  char * dst;
  char * sports;
  char * dports;
  char * interface;
{
 char * via_in = strdup("");
 char * via_out = strdup("");
 char * t;
 char * sports_as_src = NULL;
 char * sports_as_dst = NULL;
 char * dports_as_src = NULL;
 char * dports_as_dst = NULL;
 char * icmp_code;
 
 if(icmp(proto))
 {
  if(sports && strlen(sports))icmp_code = icmp_types(sports);
  else if(dports && strlen(dports))icmp_code = icmp_types(dports);
  else icmp_code = icmp_types("");
  
  dports_as_src = dports_as_dst = icmp_code;
  sports_as_src = sports_as_dst = "";
 }
 else
 {
 while((t=strchr(sports, '-')))t[0]=':';
 while((t=strchr(dports, '-')))t[0]=':';
 sports_as_src = netfilter_sports(sports);
 sports_as_dst = netfilter_dports(sports);
 
 dports_as_src = netfilter_sports(dports);
 dports_as_dst = netfilter_dports(dports);
 }
 
 

 
 if(interface)
 {
  free(via_in);
  via_in = malloc(10 + strlen(interface));
  sprintf(via_in, "-i %s", interface);
  via_out = malloc(10 + strlen(interface));
  sprintf(via_out, "-o %s", interface);
 }
  switch(op)
  {
    case ACCEPT_ONE_WAY :
      printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      break;
    case ACCEPT_ONE_WAY_REVERSE :
      printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
      break;
    case ACCEPT_TWO_WAYS :
      printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", dst, src,proto, dports_as_src, sports_as_dst, via_in);
      break;
    case ACCEPT_TWO_WAYS_ESTABLISHED :
      if(!strcmp(proto, "tcp"))
      {
       printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
       printf("$iptables -A INPUT -s %s -d %s -p %s %s %s --syn -j DENY %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
       printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
      }
      else
      {
       /* XXX stateful needed here */
       printf("# (warning. A stateful firewall would be better here)\n");
       printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
       printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", dst, src, proto,dports_as_src, sports_as_dst, via_in);
      }
      break;
     case ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE :
      if(!strcmp(proto, "tcp"))
      {
       printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
       printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s --syn -j DENY %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
       printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      }
      else
      {
       /* XXX stateful needed here */
       printf("# (warning. A stateful firewall would be better here)\n");
       printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
       printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j ACCEPT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      }
      break;  
    case DENY :
      printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j DROP %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j DROP %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
      break;
    case REJECT :
      printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j REJECT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      printf("$iptables -A INPUT -s %s  -d %s -p %s %s %s -j REJECT %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
      break;
    case DENY_OUT :
      printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j DROP %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      break;
    case DENY_IN :
      printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j DROP %s\n", dst, src, proto, dports_as_src,sports_as_dst, via_in);
      break;
    case REJECT_OUT :
      printf("$iptables -A OUTPUT -s %s -d %s -p %s %s %s -j REJECT %s\n", src, dst, proto, sports_as_src, dports_as_dst, via_out);
      break;
    case REJECT_IN :
      printf("$iptables -A INPUT -s %s -d %s -p %s %s %s -j REJECT %s\n", dst, src, proto, dports_as_src, sports_as_dst, via_in);
      break;
  }
  if(icmp(proto))
  { 
   free(icmp_code);
  }
  else
  {
  free(sports_as_src);
  free(sports_as_dst);
  free(dports_as_src);
  free(dports_as_dst);
  }
  free(via_in);
  free(via_out);
  return 0;
}



int
translate_linux_netfilter_start()
{
 printf("#!/bin/sh\n");
 printf("# Firewall rules generated by hlfl\n\n");
 printf("# WARNING : netfilter output has never been tested in real life\n");
 
 printf("iptables=\"/sbin/iptables\"\n\n");
 printf("$iptables -F\n");
 printf("$iptables -X\n\n");
 return 0;
}

void 
include_text_netfilter(c)
 char * c;
{
 if(!strncmp("if(", c, 3))
 {
  if(!strncmp("if(netfilter)", c, strlen("if(netfilter)")))
   printf("%s", c+strlen("if(netfilter)"));
 }
  else printf("%s", c);
}
