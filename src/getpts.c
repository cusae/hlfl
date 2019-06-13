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

/*---------------------------------------------------------
 *		Private functions
 *---------------------------------------------------------*/

extern char *get_definition(char *);

/*
 * 0 is considered as the biggest number, since it
 * ends our string
 */
static int qsort_compar(const void *a, const void *b)
{
	u_short *aa = (u_short *) a;
	u_short *bb = (u_short *) b;
	if (*aa == 0)
		return (1);
	else if (*bb == 0)
		return (-1);
	else
		return (*aa - *bb);
}

/*
 * getpts()
 *
 * This function is (c) Fyodor <fyodor@dhp.com> and was taken from
 * his excellent and outstanding scanner Nmap
 * See http://www.insecure.org/nmap/ for details about
 * Nmap
 */

/* Convert a string like "-100,200-1024,3000-4000,60000-" into an array
   of port numbers*/
static unsigned short *getpts(char *origexpr)
{
	int exlen = strlen(origexpr);
	char *p, *q;
	unsigned short *tmp, *ports;
	int i = 0, j = 0, start, end;
	char *expr = strdup(origexpr);
	char *mem = expr;

	ports = malloc(65536 * sizeof(short));
	for (; j < exlen; j++)
		if (expr[j] != ' ')
			expr[i++] = expr[j];
	expr[i] = '\0';
	i = 0;
	while ((p = strchr(expr, ','))) {
		*p = '\0';
		if (*expr == '-') {
			start = 1;
			end = atoi(expr + 1);
		} else {
			start = end = atoi(expr);
			if ((q = strchr(expr, '-')) && *(q + 1))
				end = atoi(q + 1);
			else if (q && !*(q + 1))
				end = 65535;
		}
		if (start < 1)
			start = 1;
		if (start > end)
			return (NULL);	/* invalid spec */
		for (j = start; j <= end; j++)
			ports[i++] = j;
		expr = p + 1;
	}
	if (*expr == '-') {
		start = 1;
		end = atoi(expr + 1);
	} else {
		start = end = atoi(expr);
		if ((q = strchr(expr, '-')) && *(q + 1))
			end = atoi(q + 1);
		else if (q && !*(q + 1))
			end = 65535;
	}
	if (start < 1 || start > end)
		return (NULL);
	for (j = start; j <= end; j++)
		ports[i++] = j;

	ports[i++] = 0;
	tmp = realloc(ports, i * sizeof(short));
	free(mem);
	qsort(tmp, i, sizeof(u_short), qsort_compar);
	return tmp;
}

int number_of_ranges(ranges)
u_short *ranges;
{
	int num = 1;
	int i = 1;
	if (!ranges)
		return 0;

	while (ranges[i]) {
		if (!((ranges[i] - 1) == ranges[i - 1]))
			num++;
		i++;
	}
	return num;
}

static char *clean_expr(expr)
char *expr;
{
	char *s = expr;
	char *e;
	char ret[65000];

	memset(ret, 0, sizeof(ret));
	if (!expr)
		return NULL;
	while ((e = strchr(s, ','))) {
		e[0] = '\0';
		/* is it a port ? */
		if (atoi(s)) {
			if (strlen(ret))
				strcat(ret, ",");
			strcat(ret, s);
		} else {
			/* it may be a definition */
			char *v = get_definition(s);
			if (v) {
				if (strlen(ret))
					strcat(ret, ",");
				strcat(ret, v);
				free(v);
			} else {
				return NULL;
			}
		}
		s = e + 1;
	}

	if (atoi(s)) {
		if (strlen(ret))
			strcat(ret, ",");
		strcat(ret, s);
	} else {
		/* it may be a definition */
		char *v = get_definition(s);
		if (v) {
			if (strlen(ret))
				strcat(ret, ",");
			strcat(ret, v);
			free(v);
		} else {
			return NULL;
		}
	}

	if (!strlen(ret))
		return strdup(expr);
	else
		return strdup(ret);
}

/*---------------------------------------------------------
 *		Public functions
 *---------------------------------------------------------*/

/*
 * This function returns the range of ports.
 *
 * ie : input  : '192.168.1.1 1-1025,80,81,82'
 *      output : {'80-82','1-1025'}
 */
char **get_ports_ranges(expr)
char *expr;
{
	u_short *ports = NULL;
	int i = 1;
	char **ret = NULL;
	int n;
	int start;
	int end;
	int current = 0;
	char *s = NULL;

	if (expr) {
		while (expr[0] == ' ')
			expr++;
		s = strchr(expr, ' ');
	}

	if (s) {
		char old_s;
		old_s = s[0];
		s[0] = '\0';
		expr = s + 1;
		expr = clean_expr(expr);
		if (!expr) {
			return NULL;
		}
		ports = getpts(expr);
		if (!ports) {
			char *ex = get_definition(expr);
			if (ex) {
				ports = getpts(ex);
			}
		}
		free(expr);
	}

	if (!s || !ports) {
		ret = malloc(2 * sizeof(char *));
		memset(ret, 0, 2 * sizeof(char *));
		ret[0] = malloc(1);
		ret[0][0] = 0;
		return ret;
	}

	n = number_of_ranges(ports);

	ret = malloc((n + 1) * sizeof(char *));
	memset(ret, 0, (n + 1) * sizeof(char *));
	start = end = ports[0];
	while (ports[i]) {
		if (((ports[i] - 1) != (ports[i - 1]))
		    && ((ports[i]) != (ports[i - 1]))) {
			ret[current] = malloc(50);
			if (end != start)
				sprintf(ret[current], "%d-%d", start, end);
			else
				sprintf(ret[current], "%d", start);
			start = end = ports[i];
			current++;
		} else
			end = ports[i];
		i++;
	}
	ret[current] = malloc(50);
	if (end != start)
		sprintf(ret[current], "%d-%d", start, end);
	else
		sprintf(ret[current], "%d", start);
	free(ports);
	/*free(expr); */
	return ret;
}

char **get_icmp_codes(codes)
char *codes;
{
	char **ret = malloc(2 * sizeof(char *));
	char *t;
	memset(ret, 0, 2 * sizeof(char *));

	if (codes) {
		while (codes[0] == ' ')
			codes++;
		t = strchr(codes, ' ');
		if (!t) {
			ret[0] = malloc(1);
			ret[0][0] = 0;
			return ret;
		} else {
			t[0] = 0;
			ret[0] = strdup(t + 1);
			return ret;
		}
	}
	return NULL;
}

void free_port_ranges(ranges)
char **ranges;
{
	int i = 0;
	while (ranges[i])
		free(ranges[i++]);
	free(ranges);
}
