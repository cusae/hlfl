#ifndef HLFL_LINUX_netfilter_H__
#define HLFL_LINUX_netfilter_H__

/* Add logging stuff while I (Carlos Villegas) am working in iptables support */
#define HLFL_LINUX_netfilter_LOG_LEVEL info
#define HLFL_LINUX_netfilter_LOG_PREFIX iptables

int translate_linux_netfilter(int, char *, char *, int, char *, char *, char *,
			      char *);
int translate_linux_netfilter_start(FILE *);
void print_comment_netfilter(char *buffer);
void include_text_netfilter(char *);

#endif				/* HLFL_LINUX_netfilter_H__ */
