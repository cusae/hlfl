#ifndef HLFL_LINUX_IPCHAINS_H__
#define HLFL_LINUX_IPCHAINS_H__

int translate_linux_ipchains(int, char *, char *, int, char *, char *, char *, char *);
int translate_linux_ipchains_start(FILE *);
void print_comment_ipchains(char *);
void include_text_ipchains(char *);

#endif				/* HLFL_LINUX_IPCHAINS_H__ */
