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

extern int matched_if;

/*------------------------------------------------------------------
 * Private functions
 *------------------------------------------------------------------*/

static char *icmp_types(type)
char *type;
{
	char *ret = malloc(40 + strlen(type));
	int num = -1;
	memset(ret, 0, 40 + strlen(type));
	if (!strlen(type))
		return ret;

	if (!strcmp(type, "echo-reply"))
		num = 0;
	else if (!strcmp(type, "destination-unreachable"))
		num = 3;
	else if (!strcmp(type, "echo-request"))
		num = 8;
	else if (!strcmp(type, "time-exceeded"))
		num = 11;
	else {
		fprintf(stderr, "Warning. Unknown icmp type '%s'\n", type);
		exit(1);
	}

	sprintf(ret, "%d", num);
	return ret;
}

/*------------------------------------------------------------------
 * Linux ipfwadm
 *------------------------------------------------------------------*/
int translate_linux_ipfwadm(op, proto, src, log, dst, sports, dports, interface)
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
		logit = " -o";

	if (icmp(proto)) {
		if (sports && strlen(sports))
			icmp_code = icmp_types(sports);
		else if (dports && strlen(dports))
			icmp_code = icmp_types(dports);
		else
			icmp_code = icmp_types("");

		sports = icmp_code;
		dports = "";
	} else {
		if (sports)
			while ((t = strchr(sports, '-')))
				t[0] = ':';
		if (dports)
			while ((t = strchr(dports, '-')))
				t[0] = ':';
	}

	if (interface) {
		free(via);
		via = malloc(10 + strlen(interface));
		sprintf(via, "-W %s", interface);
	}
	switch (op) {
	case ACCEPT_ONE_WAY:
		fprintf(fout,
			"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a accept %s\n",
			logit, src, sports, dst, dports, proto, via);
		break;
	case ACCEPT_ONE_WAY_REVERSE:
		if (!icmp(proto))	/*
					   * XXXX ugly hack here, because ifpwadm
					   * wants the icmp code to be with -S
					 */
			fprintf(fout,
				"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, dst, dports, src, sports, proto, via);
		else
			fprintf(fout,
				"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, dst, sports, src, dports, proto, via);
		break;
	case ACCEPT_TWO_WAYS:
		fprintf(fout,
			"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a accept %s\n",
			logit, src, sports, dst, dports, proto, via);
		fprintf(fout,
			"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a accept %s\n",
			logit, dst, dports, src, sports, proto, via);
		break;
	case ACCEPT_TWO_WAYS_ESTABLISHED:
		if (!strcmp(proto, "tcp")) {
			fprintf(fout,
				"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, src, sports, dst, dports, proto, via);
			fprintf(fout,
				"$ipfwadm -I%s -S %s %s -D %s %s -P %s -y -a deny %s\n",
				logit, dst, dports, src, sports, proto, via);
			fprintf(fout,
				"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, dst, dports, src, sports, proto, via);
		} else {
			/* XXX stateful needed here */
			fprintf(fout,
				"# (warning. A stateful firewall would be better here)\n");
			fprintf(fout,
				"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, src, sports, dst, dports, proto, via);
			fprintf(fout,
				"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, dst, dports, src, sports, proto, via);
		}
		break;
	case ACCEPT_TWO_WAYS_ESTABLISHED_REVERSE:
		if (!strcmp(proto, "tcp")) {
			fprintf(fout,
				"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, dst, dports, src, sports, proto, via);
			fprintf(fout,
				"$ipfwadm -O%s -S %s %s -D %s %s -P %s -y -a deny %s\n",
				logit, src, sports, dst, dports, proto, via);
			fprintf(fout,
				"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, src, sports, dst, dports, proto, via);
		} else {
			/* XXX stateful needed here */
			fprintf(fout,
				"# (warning. A stateful firewall would be better here)\n");
			fprintf(fout,
				"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, dst, dports, src, sports, proto, via);
			fprintf(fout,
				"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a accept %s\n",
				logit, src, sports, dst, dports, proto, via);
		}
		break;
	case DENY_ALL:
		fprintf(fout,
			"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a deny %s\n",
			logit, src, sports, dst, dports, proto, via);
		fprintf(fout,
			"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a deny %s\n",
			logit, dst, dports, src, sports, proto, via);
		break;
	case REJECT_ALL:
		fprintf(fout,
			"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a reject %s\n",
			logit, src, sports, dst, dports, proto, via);
		fprintf(fout,
			"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a reject %s\n",
			logit, dst, dports, src, sports, proto, via);
		break;
	case DENY_OUT:
		fprintf(fout,
			"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a deny %s\n",
			logit, src, sports, dst, dports, proto, via);
		break;
	case DENY_IN:
		fprintf(fout,
			"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a deny %s\n",
			logit, dst, dports, src, sports, proto, via);
		break;
	case REJECT_OUT:
		fprintf(fout,
			"$ipfwadm -O%s -S %s %s -D %s %s -P %s -a reject %s\n",
			logit, src, sports, dst, dports, proto, via);
		break;
	case REJECT_IN:
		fprintf(fout,
			"$ipfwadm -I%s -S %s %s -D %s %s -P %s -a reject %s\n",
			logit, dst, dports, src, sports, proto, via);
		break;
	}
	free(via);
	if (icmp_code)
		free(icmp_code);
	return 0;
}

int translate_linux_ipfwadm_start(FILE * output_file)
{
	fout = output_file;

	fprintf(fout, "#!/bin/sh\n");
	fprintf(fout, "# Firewall rules generated by hlfl\n\n");

	fprintf(fout, "ipfwadm=\"/sbin/ipfwadm\"\n\n");
	fprintf(fout, "$ipfwadm -I -f\n");
	fprintf(fout, "$ipfwadm -O -f\n");
	fprintf(fout, "$ipfwadm -F -f\n");
	fprintf(fout, "$ipfwadm -A -f\n");

	fprintf(fout, "$ipfwadm -I -p accept\n");
	fprintf(fout, "$ipfwadm -O -p accept\n");
	fprintf(fout, "$ipfwadm -F -p accept\n");

	return 0;
}

void print_comment_ipfwadm(buffer)
char *buffer;
{
	fprintf(fout, buffer);
}

void include_text_ipfwadm(c)
char *c;
{
	if (!strncmp("if(", c, 3)) {
		if (!strncmp("if(ipfwadm)", c, strlen("if(ipfwadm)"))) {
			fprintf(fout, "%s", c + strlen("if(ipfwadm)"));
			matched_if = 1;
		} else
			matched_if = 0;
	} else
		fprintf(fout, "%s", c);
}
