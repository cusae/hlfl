#ifndef HLFL_IPFILTER_H__
#define HLFL_IPFILTER_H__

int translate_ipfilter(int, char *, char *, int, char *, char *, char *,
		       char *);
int translate_ipfilter_start(FILE *);
void print_comment_ipfilter(char *);
void include_text_ipfilter(char *);

#endif				/* HLFL_IPFILTER_H__ */
