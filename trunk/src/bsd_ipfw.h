#ifndef HLFL__BSD_IPFW_H
#define HLFL__BSD_IPFW_H

int translate_bsd_ipfw(int, char *, char *, int, char *, char *, char *,
		       char *);
int translate_bsd_ipfw_start(FILE *);
void print_comment_ipfw(char *);
void include_text_ipfw();

#endif				/* HLFL__BSD_IPFW_H */
