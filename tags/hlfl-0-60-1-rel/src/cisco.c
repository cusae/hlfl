/* hlfl
 * Copyright © 2000-2003 Renaud Deraison
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

#define MAX_RULES (1024 * 5)

struct cisco_interfaces {
	char *name;
	int in;
	int out;
	char *rules[MAX_RULES];
	int num_rules;
	struct cisco_interfaces *next;
};

static struct cisco_interfaces *ci = NULL;

static FILE *fout;

extern int matched_if;

/*------------------------------------------------------------------
 * Addhock comment routines
 *------------------------------------------------------------------*/

char *strcat_and_dup(str1, str2)
char *str1;
char *str2;
{
	char *ret;
	ret = malloc(strlen(str1) + strlen(str2) + 1);
	strcpy(ret, str1);
	strcat(ret, str2);
	return ret;
}

char *cisco_add_buffer(str)
char *str;
{
	static char *buf = NULL;
	char *t;

	if (buf == NULL) {
		buf = strdup(str);
	} else {
		t = strcat_and_dup(buf, str);
		free(buf);
		buf = t;
	}
	return buf;
}

void cisco_clear_buffer(str)
char *str;
{
	str[0] = '\0';
}

void cisco_comment(buffer)
char *buffer;
{
	cisco_add_buffer("!");
	cisco_add_buffer(buffer);
	return;
}

/*------------------------------------------------------------------
 * Private utilities
 *------------------------------------------------------------------*/

static char *icmp_types(type)
char *type;
{
	char *ret = malloc(20);

	if (ret) {
		memset(ret, 0, 20);
		if (strlen(type)) {
			struct {
				char *str;
				char *msg;
			} types[] = {
				{
				"echo-reply", "echo-reply"}, {
				"destination-unreachable", "unreachable"}, {
				"echo-request", "echo"}, {
				"time-exceeded", "time-exceeded"}, {
				"source-quench", "source-quench"}, {
				"parameter-problem", "parameter-problem"}, {
				NULL, NULL}
			}, *t;

			for (t = types; t->str; t++) {
				if (!strcmp(type, t->str)) {
					sprintf(ret, t->msg);
					break;
				}
			}
			if (!t->str) {
				fprintf(stderr,
					"Warning. Unknown icmp type '%s'\n", type);
				cisco_comment("Warning. Unknown icmp type '");
				cisco_comment(type);
				cisco_comment("'\n");
			}
		}
	}
	return ret;
}

static struct cisco_interfaces *cisco_get_interface(name)
char *name;
{
	struct cisco_interfaces *c = ci;
	while (c) {
		if (!strcmp(c->name, name))
			return c;
		else
			c = c->next;
	}
	return NULL;
}

static struct cisco_interfaces *cisco_add_interface(name)
char *name;
{
	struct cisco_interfaces *c = ci, *iface;

	if (c)
		while (c->next)
			c = c->next;
	iface = malloc(sizeof(struct cisco_interfaces));
	memset(iface, 0, sizeof(*iface));
	iface->name = strdup(name);
	if (c) {
		c->next = iface;
		iface->in = c->in + 10;
		iface->out = c->out + 10;
	} else {
		ci = iface;
		iface->in = 101;
		iface->out = 102;
	}
	return iface;
}

static struct cisco_interfaces *cisco_interface(name)
char *name;
{
	struct cisco_interfaces *c = cisco_get_interface(name);

	if (!c)
		c = cisco_add_interface(name);
	return c;
}

static void cisco_add_rule(rule, interface)
char *rule;
char *interface;
{
	struct cisco_interfaces *c = cisco_interface(interface);
	char *buf = cisco_add_buffer(rule);
	c->rules[c->num_rules++] = strdup(buf);
	cisco_clear_buffer(buf);
	if (c->num_rules == MAX_RULES) {
		fprintf(stderr,
			"cisco : too many rules for one interface (above %d !)\n",
			MAX_RULES);
	}
}

void cisco_exit()
{
	struct cisco_interfaces *iface = ci;

	fprintf(fout, "\n\n!\n");
	fprintf(fout, "! ACL definitions\n!\n!\n\n\n");
	while (iface) {
		int i;
		fprintf(fout, "! clear the old acl, if any\n");
		fprintf(fout, "no ip access-list extended %d\n", iface->in);
		fprintf(fout, "no ip access-list extended %d\n", iface->out);
		fprintf(fout, "! Define a new ACL\n");
		for (i = 0; i < iface->num_rules; i++)
			fprintf(fout, "%s", iface->rules[i]);
		iface = iface->next;
		fprintf(fout, "\n\n");
	}

	iface = ci;

	fprintf(fout, "\n\n\n\n!\n! Now, apply our ACLs to each interface\n!\n");
	while (iface) {
		fprintf(fout, "\n\ninterface %s\n", iface->name);
		fprintf(fout, "\tip access-group %d in\n", iface->in);
		fprintf(fout, "\tip access-group %d out\n", iface->out);
		iface = iface->next;
	}

}

char *cisco_port(char *port)
{
	char *t;
	if (!port || !strlen(port)) {
		return strdup("");
	} else if ((t = strchr(port, '-'))) {
		char *ret = malloc(strlen(port) + 20);
		t[0] = ' ';
		sprintf(ret, "range %s", port);
		t[0] = '-';
		return ret;
	} else {
		char *ret = malloc(strlen(port) + 20);
		sprintf(ret, "eq %s", port);
		return ret;
	}
}

/*
 * Convert a cidr ip (192.168.1.1/24) to a
 * cisco netmask (192.168.1.1 0.0.0.255)

   Keep referred(*ip) contents.
 */

char *cisco_ip(char *ip)
{
	struct in_addr ia;
	char *t;
	char *ret = malloc(strlen(ip) + 20);
	int mask = 32;

	strcpy(ret, ip);

	t = strchr(ret, '/');
	if (t) {
		mask = atoi(t + 1);
		t[0] = 0;
	} else {
		mask = 32;
	}

	if (mask == 32) {
		strcat(ret, " 0.0.0.0");
		return ret;
	} else if (!mask) {
		ia.s_addr = (unsigned long) (-1);
		sprintf(t, " %s", inet_ntoa(ia));
		return ret;
	} else {
		ia.s_addr = (unsigned long) (-1);
		ia.s_addr = ia.s_addr >> (32 - mask);
		ia.s_addr = ia.s_addr << (32 - mask);
		ia.s_addr = ~ia.s_addr;
		ia.s_addr = htonl(ia.s_addr);

		sprintf(t, " %s", inet_ntoa(ia));
		return ret;
	}

	free(ret);
	return NULL;
}

/*------------------------------------------------------------------
 * CISCO rules
 *------------------------------------------------------------------*/
int translate_cisco(op, proto, src, log, dst, sports, dports, interface)
int op;
char *proto;
char *src;
int log;
char *dst;
char *sports;
char *dports;
char *interface;
{
	int ret = 0;
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

	if (icmp(proto)) {
		if (sports && strlen(sports))
			icmp_code = icmp_types(sports);
		else if (dports && strlen(dports))
			icmp_code = icmp_types(dports);
		else
			icmp_code = icmp_types("");
		sports = "";
		dports = "";
	} else {
		sports = cisco_port(sports);
		dports = cisco_port(dports);
	}

	if (proto) {
		if (!strcmp(proto, "all")) {
			p = strdup("ip");
		} else
			p = strdup(proto);
	} else
		p = strdup("");

	buffer = malloc(size);
	memset(buffer, 0, size);
	size--;

	switch (op) {
	case ACCEPT_ONE_WAY:
		if (interface) {
			c = cisco_interface(interface);
			snprintf(buffer, size,
				 "access-list %d permit %s %s %s %s %s %s %s\n",
				 c->out, p, src, sports, dst, dports, icmp_code, logit);
			cisco_add_rule(buffer, interface);

		} else {
			while (c) {
				memset(buffer, 0, size);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->out, p, dst, dports, dst,
					 dports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				c = c->next;
			}
		}
		break;
	case ACCEPT_ONE_WAY_REVERSE:
		if (interface) {
			c = cisco_interface(interface);
			snprintf(buffer, size,
				 "access-list %d permit %s %s %s %s %s %s %s\n",
				 c->in, p, dst, dports, src, sports, icmp_code, logit);
			cisco_add_rule(buffer, interface);
		} else {
			while (c) {
				memset(buffer, 0, size);

				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->in, p, dst, dports, src,
					 sports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				c = c->next;
			}
		}
		break;
	case ACCEPT_TWO_WAYS:
		if (interface) {
			c = cisco_interface(interface);
			snprintf(buffer, size,
				 "access-list %d permit %s %s %s %s %s %s %s\n",
				 c->out, p, src, sports, dst, dports, icmp_code, logit);
			cisco_add_rule(buffer, interface);
			snprintf(buffer, size,
				 "access-list %d permit %s %s %s %s %s %s %s\n",
				 c->in, p, dst, dports, src, sports, icmp_code, logit);
			cisco_add_rule(buffer, interface);
		} else {
			while (c) {

				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->out, p, src, sports, dst,
					 dports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->in, p, dst, dports, src,
					 sports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				c = c->next;
			}
		}
		break;

	case ACCEPT_TWO_WAYS_ESTABLISHED:
		if (!strcmp(proto, "tcp")) {
			if (interface) {
				c = cisco_interface(interface);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s\n",
					 c->out, p, src, sports, dst, dports, logit);
				cisco_add_rule(buffer, interface);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s established %s\n",
					 c->in, p, dst, dports, src, sports, logit);
				cisco_add_rule(buffer, interface);
			} else {
				while (c) {
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s %s\n",
						 c->out, p, src, sports,
						 dst, dports, logit);
					cisco_add_rule(buffer, c->name);
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s established %s\n",
						 c->in, p, dst, dports,
						 src, sports, logit);
					cisco_add_rule(buffer, c->name);
					c = c->next;
				}
			}
		} else {
			cisco_comment
			    (" (warning. A stateful firewall would be better here)\n");

			ret = HLFL_SYNTAX_ERROR;
			if (interface) {
				c = cisco_interface(interface);

				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->out, p, src, sports, dst,
					 dports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->in, p, dst, dports, src,
					 sports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
			} else {
				while (c) {
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s %s %s\n",
						 c->out, p, src, sports,
						 dst, dports, icmp_code, logit);
					cisco_add_rule(buffer, c->name);
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s %s %s\n",
						 c->in, p, dst, dports,
						 src, sports, icmp_code, logit);
					cisco_add_rule(buffer, c->name);
					c = c->next;
				}
			}
		}
		break;

	case ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE:
		if (!strcmp(proto, "tcp")) {
			if (interface) {
				c = cisco_interface(interface);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s\n",
					 c->in, p, dst, dports, src, sports, logit);
				cisco_add_rule(buffer, c->name);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s established %s\n",
					 c->out, p, src, sports, dst, dports, logit);
				cisco_add_rule(buffer, c->name);
			} else {
				while (c) {
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s %s\n",
						 c->in, p, dst, dports,
						 src, sports, logit);
					cisco_add_rule(buffer, c->name);
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s established %s\n",
						 c->out, p, src, sports,
						 dst, dports, logit);
					cisco_add_rule(buffer, c->name);
					c = c->next;
				}
			}
		} else {
			cisco_comment
			    (" (warning. A stateful firewall would be better here)\n");

			ret = HLFL_SYNTAX_ERROR;
			if (interface) {
				c = cisco_interface(interface);

				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->out, p, src, sports, dst,
					 dports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				snprintf(buffer, size,
					 "access-list %d permit %s %s %s %s %s %s %s\n",
					 c->in, p, dst, dports, src,
					 sports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
			} else {
				while (c) {
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s %s %s\n",
						 c->out, p, src, sports,
						 dst, dports, icmp_code, logit);
					cisco_add_rule(buffer, c->name);
					snprintf(buffer, size,
						 "access-list %d permit %s %s %s %s %s %s %s\n",
						 c->in, p, dst, dports,
						 src, sports, icmp_code, logit);
					cisco_add_rule(buffer, c->name);
					c = c->next;
				}
			}
		}
		break;

	case DENY_ALL:
	case REJECT_ALL:
		if (interface) {
			c = cisco_interface(interface);
			snprintf(buffer, size,
				 "access-list %d deny %s %s %s %s %s %s %s\n",
				 c->out, p, src, sports, dst, dports, icmp_code, logit);
			cisco_add_rule(buffer, c->name);
			snprintf(buffer, size,
				 "access-list %d deny %s %s %s %s %s %s %s\n",
				 c->in, p, dst, dports, src, sports, icmp_code, logit);
			cisco_add_rule(buffer, c->name);
		} else {
			while (c) {
				snprintf(buffer, size,
					 "access-list %d deny %s %s %s %s %s %s %s\n",
					 c->out, p, src, sports, dst,
					 dports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				snprintf(buffer, size,
					 "access-list %d deny %s %s %s %s %s %s %s\n",
					 c->in, p, dst, dports, src,
					 sports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				c = c->next;
			}
		}
		break;

	case REJECT_OUT:
	case DENY_OUT:
		if (interface) {
			c = cisco_interface(interface);

			snprintf(buffer, size,
				 "access-list %d deny %s %s %s %s %s %s %s\n",
				 c->out, p, src, sports, dst, dports, icmp_code, logit);
			cisco_add_rule(buffer, c->name);
		} else {
			while (c) {
				snprintf(buffer, size,
					 "access-list %d deny %s %s %s %s %s %s %s\n",
					 c->out, p, src, sports, dst,
					 dports, icmp_code, logit);
				cisco_add_rule(buffer, c->name);
				c = c->next;
			}
		}
		break;
	case REJECT_IN:
	case DENY_IN:
		if (interface) {
			c = cisco_interface(interface);
			snprintf(buffer, size,
				 "access-list %d deny %s %s %s %s %s %s %s\n",
				 c->in, p, dst, dports, src, sports, icmp_code, logit);
			cisco_add_rule(buffer, c->name);
		} else {
			while (c) {
				snprintf(buffer, size,
					 "access-list %d deny %s %s %s %s %s %s %s\n",
					 c->in, p, dst, dports, src,
					 sports, icmp_code, logit);
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
	else {
		free(sports);
		free(dports);
	}
	free(p);
	return ret;
}

int translate_cisco_start(FILE * output_file)
{
	fout = output_file;

	fprintf(fout, "!\n! cisco rules\n");
	fprintf(fout, "!\n! These rules have been only tested against IOS 12.1(T)\n");
	fprintf(fout, "! Firewall rules generated by hlfl\n\n");

	return 0;
}

void include_text_cisco(c)
char *c;
{
	if (!strncmp("if(", c, 3)) {
		if (!strncmp("if(cisco)", c, strlen("if(cisco)"))) {
			matched_if = 1;
			fprintf(fout, "%s", c + strlen("if(cisco)"));
		} else
			matched_if = 0;
	} else
		fprintf(fout, "%s", c);
}
