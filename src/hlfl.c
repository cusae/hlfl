/* hlfl
 * Copyright ® 2000-2003 Renaud Deraison
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

static char *translator_names[TRANSLATOR_MAX] = {
	"ipfw",
	"ipfw4",
	"ipfilter",
	"ipfwadm",
	"ipchains",
	"netfilter",
	"cisco"
};

static translator_definition translator_definitions[TRANSLATOR_MAX] = {
	{translate_bsd_ipfw_start, translate_bsd_ipfw, print_comment_ipfw,
	 include_text_ipfw, nop},
	{translate_bsd_ipfw_start, translate_bsd_ipfw, print_comment_ipfw,
	 include_text_ipfw, nop},
	{translate_ipfilter_start, translate_ipfilter,
	 print_comment_ipfilter,
	 include_text_ipfilter, nop},
	{translate_linux_ipfwadm_start, translate_linux_ipfwadm,
	 print_comment_ipfwadm, include_text_ipfwadm, nop},
	{translate_linux_ipchains_start, translate_linux_ipchains,
	 print_comment_ipchains, include_text_ipchains, nop},
	{translate_linux_netfilter_start, translate_linux_netfilter,
	 print_comment_netfilter, include_text_netfilter, nop},
	{translate_cisco_start, translate_cisco, cisco_comment,
	 include_text_cisco, cisco_exit},
};

struct definition {
	char *definition;
	char *value;
	struct definition *next;
};

struct definition *definitions = NULL;

#ifdef HAVE_GETOPT
/* option string for getopt() or getopt_long() */
char *optstr = "hvV:c:t:o:";
#ifdef HAVE_GETOPT_LONG
/* array of long option structs for getopt_long() */
struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"output", 1, 0, 'o'},
	{"type", 1, 0, 't'},
	{"version", 0, 0, 'V'},
	{"verbose", 1, 0, 'v'},
	{"check", 1, 0, 'c'},
	{0, 0, 0, 0}
};
#endif				/* HAVE_GETOPT_LONG */
int ch;
int opt_idx = 0;
#endif				/* HAVE_GETOPT */

int error = 0;
char *error_str[] = {
	HLFL_NO_ERROR_STR,
	HLFL_UNKNOWN_OP_STR,
	HLFL_UNKNOWN_PROTOCOL_STR,
	HLFL_UNKNOWN_IP_STR,
	HLFL_NO_MIX_DIFF_LEN_STR,
	HLFL_DEFINE_SYNTAX_ERROR_STR,
	HLFL_SYNTAX_ERROR_STR,
	HLFL_INCLUDE_FILE_NOT_FOUND_STR,
	HLFL_UNDEF_VAR_ERROR_STR,
	HLFL_DEFINE_RECURSIVE_STR
};

int matched_if = 0;

translator_t active_translator = TRANSLATOR_UNKNOWN;
char *output_fname = (void *) 0;

FILE *fin = (void *) 0;
FILE *fout = (void *) 0;

int verbose_level = 0;
int check_mask = 0;
int include_level = 0;

/*--------------------------------------------------------------

			    Utilities

----------------------------------------------------------------*/

void nop()
{
}

void add_definition(d, v)
char *d, *v;
{
	struct definition *k;
	k = malloc(sizeof(*k));
	k->definition = d;
	k->value = v;
	k->next = definitions;
	definitions = k;
}

char *get_definition(d)
char *d;
{
	struct definition *k = definitions;
	char *t;
	char *o_d;
	if (!d)
		return NULL;
	o_d = d = strdup(d);

	while (d[0] == ' ')
		d++;

	while (d[strlen(d) - 1] == ' ')
		d[strlen(d) - 1] = '\0';

	if ((t = strchr(d, ' ')))
		t[0] = '\0';

	while (k) {
		if (!strcmp(k->definition, d)) {
			if (t) {
				char *ret = malloc(strlen(k->value) + strlen(t + 1) + 2);
				sprintf(ret, "%s %s", k->value, t + 1);
				t[0] = ' ';
				free(o_d);
				return ret;
			} else {
				free(o_d);
				return strdup(k->value);
			}
		}
		k = k->next;
	}
	if (t)
		t[0] = ' ';
	free(o_d);
	return NULL;
}

/*
 * Remove the spaces at the start and at the end of a string
 *
 * " xxxxxx  " -> "xxxxxxx"
 */
char *remove_spaces(t)
char *t;
{
	if (!t)
		return t;

	while ((t[0] == ' ') || (t[0] == '\t'))
		t++;
	while ((t[strlen(t) - 1] == ' ') || (t[strlen(t) - 1] == '\t'))
		t[strlen(t) - 1] = '\0';
	return t;
}

void tab_2_space(t)
char *t;
{
	if (!t)
		return;

	while (t[0] != '\0') {
		if( t[0] == '\t' )
			t[0] = ' ';
		t++;
	}
	return;
}

char *next_op(op)
char *op;
{
	if (!op)
		return NULL;

	if (op) {
		while (op[0] == ' ' || (op[0] == '\t'))
			op++;
	}
	return op;
}

/*
 * Returns the integer value of the operator
 */
int int_op(char *op)
{
	struct {
		char *str;
		int len;
		int mask;
	} ops[] = {
#define DEF(str,mask) \
	{ str, strlen(str), mask },
#include "hlfl.def"
		{
		NULL, 0, 0}
#undef DEF
	}, *o;
	int ret = 0;

	while (op && strlen(op)) {
		for (o = ops; o->str; o++) {
			if (!strncmp(op, o->str, o->len))
				break;
		}
		if (o->str) {
			ret |= o->mask;
			op = next_op(op + o->len);
		} else {
			error = HLFL_SYNTAX_ERROR;
			ret = -1;
			break;
		}
	}

	if (!ret) {
		error = HLFL_UNKNOWN_OP;
		ret = -1;
	} else if (ret != -1) {
		/* Sanity checks */
		if (((ret & (ACCEPT | DENY | REJECT)) != ACCEPT) &&
		    ((ret & (ACCEPT | DENY | REJECT)) != DENY) &&
		    ((ret & (ACCEPT | DENY | REJECT)) != REJECT)) {
			error = HLFL_SYNTAX_ERROR;
			ret = -1;
		} else {
			if ((ret == ACCEPT) || (ret == DENY)
			    || (ret == REJECT))
				ret |= TWO_WAYS;
			if ((ret | LOG) == (ACCEPT | ESTABLISHED | TWO_WAYS | LOG))
				ret -= ESTABLISHED;	/* XXX fixme ! */
		}
	}
	return ret;
}

int icmp(proto)
char *proto;
{
	return !strcmp(proto, "icmp");
}

/*
 * returns TRUE if proto in {all, tcp, udp, icmp)
 */
int check_proto(proto)
char *proto;
{
	if ((!strcmp(proto, "all")) ||
	    (!strcmp(proto, "tcp")) ||
	    (!strcmp(proto, "udp")) ||
	    (!strcmp(proto, "icmp")))
		return 0;
	else
		return 1;
}

char **translate_proto(proto)
char *proto;
{
	char *t;
	char *s;
	char **ret;
	int current = 0;

	ret = malloc((MAX_PROTOS + 1) * sizeof(char *));
	memset(ret, 0, sizeof(char *) * (MAX_PROTOS + 1));

	t = proto;
	if ((s = strchr(t, '|'))) {
		while (s) {
			s[0] = '\0';
			if (check_proto(remove_spaces(t))) {
				error = HLFL_UNKNOWN_PROTOCOL;
				return NULL;
			}
			if (current + 1 >= MAX_PROTOS) {
				error = HLFL_TOO_MANY_PROTOCOLS;
				return NULL;
			}
			ret[current++] = strdup(t);
			t = s + 1;
			s[0] = '|';
			s = strchr(t, '|');
		}
	} else {
		if (check_proto(remove_spaces(t))) {
			error = HLFL_UNKNOWN_PROTOCOL;
			return NULL;
		}
	}
	ret[current++] = strdup(t);
	ret[current] = NULL;
	return ret;
}

/*
 * Returns number of elements in an array of strings
 */
int length(s)
char **s;
{
	int r = 0;
	while (s[r++]);
	return r - 1;
}

/*
 * Returns nonzero if the IP adress <s> is valid (of the form x.y.z.t)
 */
int valid_ip(s)
char *s;
{
	struct in_addr ia;
	char *t;
	char *m;
	int ok = 0;
	while (s[0] == ' ')
		s++;
	while (s[strlen(s) - 1] == ' ')
		s[strlen(s) - 1] = '\0';
	if ((t = strchr(s, ' ')))
		t[0] = '\0';
	if ((m = strchr(s, '/')))
		m[0] = '\0';
	ok = inet_aton(s, &ia);
	if (t)
		t[0] = ' ';
	if (m)
		m[0] = '/';
	return ok;
}

/*
 * Convert : "ip ports |  ip ports | ip ports" to
 * an array of strings
 */
char **ip(src, level)
char *src;
int level;
{
	int n = MAX_NETS;
	char *t, *s;
	char **ret;
	int current = 0;

	if (level > MAX_NETS) {
		error = HLFL_DEFINE_RECURSIVE;
		return NULL;
	}
	if (!src)
		return NULL;

	/*
	 * Double the src string, else multiple interface won't have
	 * multiple ip
	 */

	t = strdup(src);

	ret = malloc(n * sizeof(char *));
	memset(ret, 0, n * sizeof(char *));

	while (t) {
		t = remove_spaces(t);
		s = strchr_items(t, '|', '(', ')');
		if (s)
			s[0] = '\0';

		if (!valid_ip(t)) {

			/*
			 * 't' is not a valid ip (x.y.z.t)
			 *
			 * Either it's a set of IPs ('(x.y.z.t|x2.y2.z2.t2|....)')
			 * or it is a defined symbol
			 */
			char *v;
			char *w;

			/*
			 * Case #1 : subset of IPs
			 */
			if ((t[0] == '(')
			    && (w = matching_items(t, '(', ')'))) {
				int i = 0;
				char *end;
				char **r;
				t++;
				w[0] = '\0';
				end = w + 1;
				r = ip(t, level + 1);
				if (!r) {
					if (!error)
						error = HLFL_UNDEF_VAR_ERROR;
					return NULL;
				}
				while (r[i]) {
					ret[current] =
					    malloc(strlen(end) + strlen(r[i]) + 1);
					sprintf(ret[current], "%s%s", r[i], end);
					current++;
					i++;
				}
				current--;
				w[0] = ')';
			}

			/*
			 * Case #2 : a definition
			 */
			else if ((v = get_definition(t))) {
				int i = 0;
				char **r;
				r = ip(v, level + 1);
				if (!r) {
					return NULL;
				}
				while (r[i]) {
					if (current >= MAX_NETS) {
						error = HLFL_DEFINE_RECURSIVE;
						return NULL;
					}
					ret[current] = r[i];
					current++;
					i++;
				}
				current--;	/* go back one step */
				free(r);
			}

			/*
			 * Case #3 : Syntax error
			 */
			else {
				return NULL;	/* error */
			}
		} else
			ret[current] = strdup(t);
		current++;
		if (s)
			t = s + 1;
		else
			t = NULL;
	}
	return ret;
}

/*
 * Convert "iface1,iface2..." to an array of interfaces
 */
char **ifaces(iface, level)
char *iface;
int level;
{
	int n = MAX_IFACES;
	char *t, *s;
	char **ret;
	int current = 0;

	if (level > MAX_IFACES) {
		error = HLFL_DEFINE_RECURSIVE;
		return NULL;
	}
	if (!iface) {
		ret = malloc(sizeof(char *) * 2);
		ret[0] = strdup("");
		ret[1] = NULL;
		return ret;
	}

	ret = malloc(n * sizeof(char *));
	memset(ret, 0, n * sizeof(char *));

	t = iface;
	while (t) {
		char *v;
		t = remove_spaces(iface);
		s = strchr(t, ',');
		if (s)
			s[0] = '\0';
		if ((v = get_definition(t))) {
			int i = 0;
			char **r;
			r = ifaces(v, level + 1);
			if (!r) {
				return NULL;
			}
			while (r[i]) {
				if (current >= MAX_IFACES) {
					error = HLFL_DEFINE_RECURSIVE;
					return NULL;
				}
				ret[current++] = r[i++];
			}
			free(r);
		} else {
			ret[current++] = strdup(t);
		}
		if (s)
			t = s + 1;
		else
			t = NULL;
	}
	return ret;
}

/*-------------------------------------------------------------------

		       Translator function

---------------------------------------------------------------------*/

/*
 * The function that calls the appropriate translator...
 */
int translate(proto, src, op, dst, interface, flags)
char *proto;
char *src;
char *op;
char *dst;
char *interface;
char *flags;
{
	int opi = int_op(op);
	char **srcs = NULL;
	char **dsts = NULL;
	int mix = 1;
	char *iface = NULL;
	char **protos;
	char **interfaces = NULL;
	int ni = 0;
	int log = 0;

	if ((iface = get_definition(interface))) {
		interface = iface;
	}

	if (opi < 0)
		return opi;

	if (opi & LOG) {
		log++;
		opi -= LOG;
	}
	if (!(protos = translate_proto(proto))) {
		error = HLFL_UNKNOWN_PROTOCOL;
		return -1;
	}

	interfaces = ifaces(interface, 0);

	while (interfaces[ni]) {
		int np = 0;
		while (protos[np]) {
			if (flags && strstr(flags, "nomix"))
				mix = 0;

			srcs = ip(src, 0);
			dsts = ip(dst, 0);

			if (!srcs || !dsts) {
				if (!error)
					error = HLFL_UNKNOWN_IP;
				return -1;
			}

			if (mix) {
				int i = 0;
				while (srcs[i]) {
					int j = 0;
					while (dsts[j]) {
						char **sports;
						char **dports;
						int k = 0;
						char *s, *d;

						s = strdup(srcs[i]);
						d = strdup(dsts[j]);

						if (!icmp(protos[np])) {
							sports = get_ports_ranges(s);
							dports = get_ports_ranges(d);
						} else {
							sports = get_icmp_codes(s);
							dports = get_icmp_codes(d);
						}

						if (!sports || !dports) {
							error = HLFL_UNDEF_VAR_ERROR;
							return -1;
						}
						while (sports[k]) {
							int l = 0;
							while (dports[l]) {
								translator_definitions
								    [active_translator].
								    translate_func
								    (opi,
								     protos
								     [np],
								     s,
								     log,
								     d,
								     sports
								     [k],
								     dports
								     [l],
								     strlen
								     (interfaces[ni])
								     ?
								     interfaces
								     [ni] : NULL);
								l++;
							}
							k++;
						}
						free_port_ranges(sports);
						free_port_ranges(dports);
						free(s);
						free(d);
						j++;
					}
					i++;
				}
			} else {
				/* no mix */
				if (length(srcs) != length(dsts)) {
					error = HLFL_NO_MIX_DIFF_LEN;
					return -1;
				} else {
					int i = 0;
					while (srcs[i]) {
						char **sports;
						char **dports;
						char *s, *d;
						int k = 0;

						s = strdup(srcs[i]);
						d = strdup(dsts[i]);
						sports = get_ports_ranges(s);
						dports = get_ports_ranges(d);
						while (sports[k]) {
							int l = 0;
							while (dports[l]) {
								translator_definitions
								    [active_translator].
								    translate_func
								    (opi,
								     protos
								     [np],
								     s,
								     log,
								     d,
								     sports
								     [k],
								     dports
								     [l],
								     strlen
								     (interfaces[ni])
								     ?
								     interfaces
								     [ni] : NULL);
								l++;
							}
							k++;
						}
						free_port_ranges(sports);
						free_port_ranges(dports);
						i++;
					}
				}
			}
			np++;
		}
		ni++;
	}

	if (iface)
		free(iface);
	free(srcs);
	free(dsts);
	free(protos);
	return 0;
}

/*---------------------------------------------------------------------

			       (ugly) Parser

-----------------------------------------------------------------------*/

/*
 * Include a file
 */
int include(file)
char *file;
{
	FILE *f;

	while (file[strlen(file) - 1] == '\n')
		file[strlen(file) - 1] = '\0';
	file = remove_spaces(file);
	if (file[0] == '<') {
		if (file[strlen(file) - 1] != '>') {
			error = HLFL_SYNTAX_ERROR;
			return -1;
		} else {

			char *path = malloc(strlen(FILES) + strlen(file) + 2);

			file[strlen(file) - 1] = '\0';
			file++;
			sprintf(path, "%s%s%s", FILES,
				FILES[strlen(FILES) - 1] == '/' ? "" : "/", file);;
			f = fopen(path, "r");
			if (!f) {
				error = HLFL_INCLUDE_FILE_NOT_FOUND;
				return -1;
			}
			read_file(f, file);
			fclose(f);
		}
	} else {
		f = fopen(file, "r");
		if (!f) {
			error = HLFL_INCLUDE_FILE_NOT_FOUND;
			return -1;
		} else {
			read_file(f, file);
			fclose(f);
		}
	}
	return 0;
}

/*
 * Define a variable
 *
 *
 * 'order' is : 'name value'
 *
 */
int define(order)
char *order;
{
	char *t;
	char *def;
	char *value;
	char oldt;
	t = strchr(order, ' ');
	if (!t) {
		error = HLFL_DEFINE_SYNTAX_ERROR;
		return -1;
	}

	oldt = t[0];
	t[0] = '\0';
	def = strdup(order);
	value = strdup(t + 1);
	t[0] = oldt;
	while ((value[strlen(value) - 1] == '\n')
	       || (value[strlen(value) - 1] == ' '))
		value[strlen(value) - 1] = '\0';

	add_definition(def, value);
	return 0;
}

/*
 * Process one single line
 */
int process(buffer)
char *buffer;
{
	char *t = buffer;

	char *proto;
	char *src;
	char *dst;
	char *op;
	char *interface = NULL;
	char *flags;
	char old_t;
	int n;

	while ((t[0] == ' ') || (t[0] == '\t') || (t[0] == '\n'))
		t++;

	/*
	 * Drop the comments
	 */
	if ((t[0] == '%') || !t[0])
		return 0;

	if (t[0] == '#')
		return COMMENT;

	if (t[0] == '!')
		return INCLUDE_TEXT;

	/*
	 * Our syntax is :
	 *
	 *     proto (src) op (dst) [interface] flags
	 */

	tab_2_space(t);

	/* proto */
	proto = t;
	t = strchr(proto + 1, ' ');

	if (!t) {
		t = strchr(proto + 1, '(');
		if (!t) {
			error = HLFL_SYNTAX_ERROR;
			return -1;
		}
	}
	old_t = t[0];
	t[0] = '\0';

	proto = strdup(proto);
	t[0] = old_t;
	if (!strcmp(proto, "define")) {
		return define(t + 1);
	}

	else if (!strcmp(proto, "include")) {
		return include(t + 1);
	}

	else {
		while (t[0] == ' ')
			t++;

		/* src */
		if (t[0] != '(') {

			error = HLFL_SYNTAX_ERROR;
			return -1;
		}

		src = t + 1;
		t = matching_items(t, '(', ')');

		if (!t) {
			error = HLFL_SYNTAX_ERROR;
			return -1;
		}
		old_t = t[0];
		t[0] = '\0';
		src = strdup(src);
		t[0] = old_t;

		t++;
		while ((t[0] == ' ') || (t[0] == '\t'))
			t++;

		/* op */
		op = t;

		t = strchr(op + 1, '(');
		if (!t) {
			error = HLFL_SYNTAX_ERROR;
			return -1;
		}
		old_t = t[0];
		t[0] = '\0';
		op = strdup(op);
		t[0] = old_t;

		while ((t[0] == ' ') || (t[0] == '\t'))
			t++;

		/* dst */
		if (t[0] != '(') {
			error = HLFL_SYNTAX_ERROR;
			return -1;
		}

		dst = t + 1;
		t = matching_items(t, '(', ')');

		if (!t) {
			error = HLFL_SYNTAX_ERROR;
			return -1;
		}

		old_t = t[0];
		t[0] = '\0';
		dst = strdup(dst);
		t[0] = old_t;
		t++;
		while ((t[0] == ' ') || (t[0] == '\t'))
			t++;

		/* interface (optional) */

		if (t[0] == '[') {
			interface = t + 1;
			t = matching_items(t, '[', ']');
			if (!t) {
				error = HLFL_SYNTAX_ERROR;
				return -1;
			}
			t[0] = '\0';
			interface = strdup(interface);
			t++;
			while (t[0] == ' ')
				t++;
		} else if (!strncmp(t, "on", 2)) {
			t += 2;
			while (t[0] == ' ')
				t++;
			if (t[0] == '(') {
				interface = t + 1;
				if (!(t = matching_items(t, '(', ')'))) {
					error = HLFL_SYNTAX_ERROR;
					return -1;
				}
				t[0] = '\0';
				interface = strdup(interface);
				t++;
				while (t[0] == ' ')
					t++;
			} else if (t[0] == '[') {
				interface = t + 1;
				if (!(t = matching_items(t, '[', ']'))) {
					error = HLFL_SYNTAX_ERROR;
					return -1;
				}
				t[0] = '\0';
				interface = strdup(interface);
				t++;
				while (t[0] == ' ')
					t++;
			} else {
				interface = t;
				t = strchr(t + 1, ' ');
				if (t)
					t[0] = '\0';
				interface = strdup(interface);
				if (interface[strlen(interface) - 1] == '\n')
					interface[strlen(interface) - 1] = '\0';
				if (t) {
					t++;
					while (t[0] && t[0] == ' ')
						t++;
				}
			}
		}
		/* extra flags (optional) */

		if (t && t[0] && (t[0] != '\n')) {
			flags = strdup(t);
		} else
			flags = NULL;

		n = translate(remove_spaces(proto),
			      remove_spaces(src),
			      remove_spaces(op),
			      remove_spaces(dst),
			      remove_spaces(interface), remove_spaces(flags));
		free(proto);
		free(src);
		free(dst);
		free(op);
		free(interface);
		free(flags);
		return n;
	}
}

void read_file(file, fname)
FILE *file;
char *fname;
{
	char buffer[4096];
	int line = 0;
	memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer) - 1, file)) {
		int n;
		line++;
#if DEBUG
		printf("%s\n", buffer);
#endif
		if ((n = process(buffer)) < 0) {
			fprintf(stderr, "*** %s : Error line %d : %s\n",
				fname, line, error_str[error]);
			exit(1);
		}
		if (n == COMMENT)
			translator_definitions[active_translator].comment(buffer);
		else if (n == INCLUDE_TEXT) {
			char *t = buffer;
			while (t[0] == '\n' || t[0] == '\t' || t[0] == ' ')
				t++;
			t++;	/* t[0] == '!' */
			while (t[0] == '\n' || t[0] == '\t' || t[0] == ' ')
				t++;

			if (!strncmp(t, "else", strlen("else"))) {
				if (!matched_if)
					printf("%s", t + strlen("else"));
			} else
				translator_definitions[active_translator].
				    include_text_func(t);
		}
		memset(buffer, 0, sizeof(buffer));
	}
}

translator_t translator_name_to_type(name)
char *name;
{

	translator_t result = TRANSLATOR_UNKNOWN;
	int i;

	for (i = 0; i < TRANSLATOR_MAX; i++)
		if (strcmp(translator_names[i], name) == 0) {
			result = i;
			break;
		}

	return (result);
}

/*---------------------------------------------------------------------

				main()

-----------------------------------------------------------------------*/

void usage(n)
char *n;
{

	fprintf(stderr, "%s v%s\n", n, VERSION);
	fprintf(stderr,
		"Copyright © 2000-2003 Renaud Deraison (deraison @ hlfl.org)\n\n");
	fprintf(stderr, "Usage: %s [OPTIONS] <rulefile>\n\n", n);
	fprintf(stderr, "Operation modes:\n");
	fprintf(stderr, "   -h"
#ifdef HAVE_GETOPT_LONG
			", --help"
#endif
			"\t\tprint this help and exit\n");
	fprintf(stderr, "   -V"
#ifdef HAVE_GETOPT_LONG
			", --version"
#else
			"\t"
#endif
			"\tprint version number, then exit\n");
	fprintf(stderr, "   -v"
#ifdef HAVE_GETOPT_LONG
			", --verbose"
#else
			"\t"
#endif
			"\tbe verbose, print comments\n");
	fprintf(stderr, "   -c"
#ifdef HAVE_GETOPT_LONG
			", --check\t"
#else
			"\t"
#endif
			"\tcheck netmasks before computing\n");
	fprintf(stderr,	"   -t"
#ifdef HAVE_GETOPT_LONG
			", --type="
#endif
			"TYPE\tgenerate output formatted for TYPE of firewall\n");
	fprintf(stderr, "   -o"
#ifdef HAVE_GETOPT_LONG
			", --output="
#endif
			"FILE\tsave output in FILE (stdout is the default)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "TYPE options are:\n");
	fprintf(stderr, "   ipfw - BSD ipfw\n");
	fprintf(stderr, "   ipfw4 - BSD ipfw 4 (stateful)\n");
	fprintf(stderr, "   ipfilter - Darren Reeds's ipfilter\n");
	fprintf(stderr, "   ipfwadm - Linux 2.0.x ipfwadm\n");
	fprintf(stderr, "   ipchains - Linux 2.2.x ipchains\n");
	fprintf(stderr, "   netfilter - Linux 2.4.x netfilter\n");
	fprintf(stderr, "   cisco - Cisco rules (IOS 12.1(2)T)\n\n");
	exit(1);
}

void version(n)
char *n;
{
	fprintf(stderr, "%s v%s\n", n, VERSION);
	exit(1);
}

int main(argc, argv)
int argc;
char **argv;
{
#ifdef HAVE_GETOPT

#ifdef HAVE_GETOPT_LONG
	while ((ch = getopt_long(argc, argv, optstr, long_options, &opt_idx)) != -1) {
#else
	while ((ch = getopt(argc, argv, optstr)) != -1) {
#endif
		switch (ch) {
		case 'h':{
				usage(argv[0]);
				break;
			}
		case 'v':{
				verbose_level = atoi(optarg);
				break;
			}
		case 'V':{
				version(argv[0]);
				break;
			}
		case 'c':{
				check_mask = atoi(optarg);
				break;
			}
		case 't':{
				active_translator = translator_name_to_type(optarg);
				break;
			}
		case 'o':{
				output_fname = strdup(optarg);
				break;
			}
		default:{
				usage(argv[0]);
			}
		}

	}

	if (active_translator != TRANSLATOR_UNKNOWN) {

		/*
		 * Always define the symbol 'any'
		 */
		add_definition("any", "0.0.0.0/0");

		if (output_fname)
			fout = fopen(output_fname, "w");

		translator_definitions[active_translator].
		    translator_start((fout != (void *) 0) ? fout : stdout);

		if (optind < argc) {
			char *input_fname;	/* name of rule file to read */

			while (optind < argc) {
				input_fname = argv[optind++];

				if ((fin = fopen(input_fname, "r")) != (void *) 0) {
					read_file(fin, input_fname);
					translator_definitions
					    [active_translator].exit_func();
					fclose(fin);
				} else
					fprintf(stderr,
						"%s: Could not read rule file '%s'.\n",
						argv[0], input_fname);

			}
		} else {
			read_file(stdin, "stdin");
			translator_definitions[active_translator].exit_func();
		}
	} else {
		fprintf(stderr, "%s: No output type specified.\n\n", argv[0]);
		usage(argv[0]);
	}

	if (fout != (void *) 0)
		fclose(fout);

	if (output_fname != (void *) 0)
		free(output_fname);

#endif				/* HAVE_GETOPT */

	return 0;
}
