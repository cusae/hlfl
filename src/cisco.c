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
#include "ipfilter.h"

#define MAX_RULES 1024


struct cisco_interfaces {
 char *name;
 int in;
 int out;
 char *rules[MAX_RULES];
 int num_rules;
 struct cisco_interfaces *next;
};

static struct cisco_interfaces *ci = NULL;

extern int matched_if;



/*------------------------------------------------------------------
 * Private utilities
 *------------------------------------------------------------------*/





static char *
icmp_types(type)
 char *type;
{
 char *ret = malloc(20);
 bzero(ret, 20);
 if (!strlen(type))
  return ret;
 if (!strcmp(type, "echo-reply"))
  sprintf(ret, "echo-reply");
 else if (!strcmp(type, "destination-unreachable"))
  sprintf(ret, "unreachable");
 else if (!strcmp(type, "echo-request"))
  sprintf(ret, "echo");
 else if (!strcmp(type, "time-exceeded"))
  sprintf(ret, "time-exceeded");
 else
  fprintf(stderr, "Warning. Unknown icmp type '%s'\n", type);
 return ret;
}
static struct cisco_interfaces *
cisco_get_interface(name)
 char *name;
{
 struct cisco_interfaces *c = ci;
 while (c)
   {
    if (!strcmp(c->name, name))
     return c;
    else
     c = c->next;
   }
 return NULL;
}


static struct cisco_interfaces *
cisco_add_interface(name)
 char *name;
{
 struct cisco_interfaces *c = ci, *iface;

 if (c)
  while (c->next)
   c = c->next;
 iface = malloc(sizeof(struct cisco_interfaces));
 bzero(iface, sizeof(*iface));
 iface->name = strdup(name);
 if (c)
   {
    c->next = iface;
    iface->in = c->in + 10;
    iface->out = c->out + 10;
   }
 else
   {
    ci = iface;
    iface->in = 101;
    iface->out = 102;
   }
 return iface;
}

static struct cisco_interfaces *
cisco_interface(name)
 char *name;
{
 struct cisco_interfaces *c = cisco_get_interface(name);

 if (!c)
  c = cisco_add_interface(name);
 return c;
}



static void
cisco_add_rule(rule, interface)
 char *rule;
 char *interface;
{
 struct cisco_interfaces *c = cisco_interface(interface);
 c->rules[c->num_rules++] = strdup(rule);
 if (c->num_rules == MAX_RULES)
   {
    fprintf(stderr, "cisco : too many rules for one interface (above %d !)\n",
	    MAX_RULES);
   }
}


void
cisco_exit()
{
 struct cisco_interfaces *iface = ci;
 
 printf("\n\n!\n");
 printf("! ACL definitions\n!\n!\n\n\n");
 while(iface)
   {
     int i;
     printf("! clear the old acl, if any\n");
     printf("no ip access-list extended %d\n", iface->in);
     printf("no ip access-list extended %d\n", iface->out);
     printf("! Define a new ACL\n");
     for (i = 0; i < iface->num_rules; i++)
     printf("%s", iface->rules[i]);
     iface = iface->next;
     printf("\n\n");
   }
   
 iface = ci;
 
 printf("\n\n\n\n!\n! Now, apply our ACLs to each interface\n!\n");
 while (iface)
   {
    printf("\n\ninterface %s\n", iface->name);
    printf("\tip access-group %d in\n", iface->in);
    printf("\tip access-group %d out\n", iface->out);
    iface = iface->next;
   }

   
}

char *
cisco_port(char *port)
{
 char *t;
 if (!port || !strlen(port))
   {
    return strdup("");
   }
 else if ((t = strchr(port, '-')))
   {
    char *ret = malloc(strlen(port) + 20);
    t[0] = ' ';
    sprintf(ret, "range %s", port);
    t[0] = '-';
    return ret;
   }
 else
   {
    char *ret = malloc(strlen(port) + 20);
    sprintf(ret, "eq %s", port);
    return ret;
   }
}

/*
 * Convert a cidr ip (192.168.1.1/24) to a
 * cisco netmask (192.168.1.1 0.0.0.255)
 */

char *
cisco_ip(char *ip)
{
 struct in_addr ia;
 char *t;

 t = strchr(ip, '/');
 if (!t)
  return strdup(ip);

 if (t)
   {
    int mask = atoi(t + 1);
    t[0] = 0;
    if (mask == 32)
      {
       return strdup(ip);
      }
    else if (!mask)
      {
       char *ret = malloc(40);
       ia.s_addr = (unsigned long) (-1);
       sprintf(ret, "%s %s", ip, inet_ntoa(ia));
       return ret;
      }
    else
      {
       char *ret = malloc(40);
       ia.s_addr = (unsigned long) (-1);
       ia.s_addr = ia.s_addr >> (32 - mask);
       ia.s_addr = ia.s_addr << (32 - mask);
       ia.s_addr = ~ia.s_addr;
       ia.s_addr = htonl(ia.s_addr);

       sprintf(ret, "%s %s", ip, inet_ntoa(ia));
       return ret;
      }
   }
 return NULL;
}

/*------------------------------------------------------------------
 * CISCO rules
 *------------------------------------------------------------------*/
int
translate_cisco(op, proto, src, log, dst, sports, dports, interface)
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
 char *p;
 struct cisco_interfaces *c = ci;
 char *icmp_code = "";
 char *buffer;
 int size = 1024;
 char *logit = "";

/* XXX to complete */
/* XXX complete also the rest of the code when knowing specifical place of the keyword */
 if (log)
  logit = "log";

 src = cisco_ip(src);
 dst = cisco_ip(dst);

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
    sports = cisco_port(sports);
    dports = cisco_port(dports);
   }

 if (proto)
   {
    if (!strcmp(proto, "all"))
      {
       p = strdup("ip");
      }
    else
     p = strdup(proto);
   }
 else
  p = strdup("");



 buffer = malloc(size);
 bzero(buffer, size);
 size--;

 switch (op)
   {
   case ACCEPT_ONE_WAY:
    if (interface)
      {
       c = cisco_interface(interface);
       snprintf(buffer, size,
		"access-list %d permit %s %s %s %s %s %s %s\n", c->out, p,
		src, sports, dst, dports, icmp_code, logit);
       cisco_add_rule(buffer, interface);

      }
    else
      {
       while (c)
	 {
	  bzero(buffer, size);
	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->out, p, dst, dports, dst, dports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  c = c->next;
	 }
      }
    break;
   case ACCEPT_ONE_WAY_REVERSE:
    if (interface)
      {
       c = cisco_interface(interface);
       snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		c->in, p, dst, dports, src, sports, icmp_code, logit);
       cisco_add_rule(buffer, interface);
      }
    else
      {
       while (c)
	 {
	  bzero(buffer, size);

	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->in, p, dst, dports, src, sports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  c = c->next;
	 }
      }
    break;
   case ACCEPT_TWO_WAYS:
    if (interface)
      {
       c = cisco_interface(interface);
       snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		c->out, p, src, sports, dst, dports, icmp_code, logit);
       cisco_add_rule(buffer, interface);
       snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		c->in, p, dst, dports, src, sports, icmp_code, logit);
       cisco_add_rule(buffer, interface);
      }
    else
      {
       while (c)
	 {

	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->out, p, src, sports, dst, dports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->in, p, dst, dports, src, sports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  c = c->next;
	 }
      }
    break;

   case ACCEPT_TWO_WAYS_ESTABLISHED:
    if (!strcmp(proto, "tcp"))
      {
       if (interface)
	 {
	  c = cisco_interface(interface);
	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s\n",
		   c->out, p, src, sports, dst, dports, logit);
	  cisco_add_rule(buffer, interface);
	  snprintf(buffer, size,
		   "access-list %d permit %s %s %s %s %s established %s\n", c->in,
		   p, dst, dports, src, sports, logit);
	  cisco_add_rule(buffer, interface);
	 }
       else
	 {
	  while (c)
	    {

	     snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s\n",
		      c->out, p, src, sports, dst, dports, logit);
	     cisco_add_rule(buffer, c->name);
	     snprintf(buffer, size,
		      "access-list %d permit %s %s %s %s %s established %s\n",
		      c->in, p, dst, dports, src, sports, logit);
	     cisco_add_rule(buffer, c->name);
	     c = c->next;
	    }
	 }
      }
    else
      {
       if (interface)
	 {
	  c = cisco_interface(interface);

	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->out, p, src, sports, dst, dports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->in, p, dst, dports, src, sports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	 }
       else
	 {
	  while (c)
	    {

	     snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		      c->out, p, src, sports, dst, dports, icmp_code, logit);
	     cisco_add_rule(buffer, c->name);
	     snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		      c->in, p, dst, dports, src, sports, icmp_code, logit);
	     cisco_add_rule(buffer, c->name);
	     c = c->next;
	    }
	 }
      }
    break;

   case ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE:
    if (!strcmp(proto, "tcp"))
      {
       if (interface)
	 {
	  c = cisco_interface(interface);
	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s\n",
		   c->in, p, dst, dports, src, sports, logit);
	  cisco_add_rule(buffer, c->name);
	  snprintf(buffer, size,
		   "access-list %d permit %s %s %s %s %s established %s\n", c->out,
		   p, src, sports, dst, dports, logit);
	  cisco_add_rule(buffer, c->name);
	 }
       else
	 {
	  while (c)
	    {
	     snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s\n",
		      c->in, p, dst, dports, src, sports, logit);
	     cisco_add_rule(buffer, c->name);
	     snprintf(buffer, size,
		      "access-list %d permit %s %s %s %s %s established %s\n",
		      c->out, p, src, sports, dst, dports, logit);
	     cisco_add_rule(buffer, c->name);
	     c = c->next;
	    }
	 }
      }
    else
      {
       if (interface)
	 {
	  c = cisco_interface(interface);

	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->out, p, src, sports, dst, dports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		   c->in, p, dst, dports, src, sports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	 }
       else
	 {
	  while (c)
	    {
	     snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		      c->out, p, src, sports, dst, dports, icmp_code, logit);
	     cisco_add_rule(buffer, c->name);
	     snprintf(buffer, size, "access-list %d permit %s %s %s %s %s %s %s\n",
		      c->in, p, dst, dports, src, sports, icmp_code, logit);
	     cisco_add_rule(buffer, c->name);
	     c = c->next;
	    }
	 }
      }
    break;


   case DENY_ALL:
   case REJECT_ALL:
    if (interface)
      {
       c = cisco_interface(interface);
       snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n", c->out,
		p, src, sports, dst, dports, icmp_code, logit);
       cisco_add_rule(buffer, c->name);
       snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n", c->in,
		p, dst, dports, src, sports, icmp_code, logit);
       cisco_add_rule(buffer, c->name);
      }
    else
      {
       while (c)
	 {
	  snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n",
		   c->out, p, src, sports, dst, dports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n",
		   c->in, p, dst, dports, src, sports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  c = c->next;
	 }
      }
    break;

   case REJECT_OUT:
   case DENY_OUT:
    if (interface)
      {
       c = cisco_interface(interface);

       snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n", c->out,
		p, src, sports, dst, dports, icmp_code, logit);
       cisco_add_rule(buffer, c->name);
      }
    else
      {
       while (c)
	 {
	  snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n",
		   c->out, p, src, sports, dst, dports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  c = c->next;
	 }
      }
    break;
   case REJECT_IN:
   case DENY_IN:
    if (interface)
      {
       c = cisco_interface(interface);
       snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n", c->in,
		p, dst, dports, src, sports, icmp_code, logit);
       cisco_add_rule(buffer, c->name);
      }
    else
      {
       while (c)
	 {
	  snprintf(buffer, size, "access-list %d deny %s %s %s %s %s %s %s\n",
		   c->in, p, dst, dports, src, sports, icmp_code, logit);
	  cisco_add_rule(buffer, c->name);
	  c = c->next;
	 }
      }
    break;


   }

 free(via);
 free(src);
 free(dst);

 if (icmp(proto))
  free(icmp_code);
 else
   {
    free(sports);
    free(dports);
   }
 free(p);
 return 0;
}


int
translate_cisco_start()
{
 printf("!\n! cisco rules\n");
 printf("!\n! These rules have been only tested against IOS 12.1(T)\n");
 printf("! Firewall rules generated by hlfl\n\n");
 return 0;
}

/*
 * Because the cisco rules are sorted by interface, we
 * do not print comments
 */
void
cisco_comment(void)
{
 return;
}

void
include_text_cisco(c)
 char *c;
{
 if (!strncmp("if(", c, 3))
   {
    if (!strncmp("if(cisco)", c, strlen("if(cisco)")))
     {
      matched_if = 1;
      printf("%s", c + strlen("if(cisco)"));
     }
     else
      matched_if = 0;
   }
 else
  printf("%s", c);
}
