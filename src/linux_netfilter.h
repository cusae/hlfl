#ifndef HLFL_LINUX_netfilter_H__
#define HLFL_LINUX_netfilter_H__

int translate_linux_netfilter(int, char *, char *, int, char *, char *, char *,
			      char *);
int translate_linux_netfilter_start(FILE *);
void print_comment_netfilter(char *buffer);
void include_text_netfilter(char *);

#endif				/* HLFL_LINUX_netfilter_H__ */
