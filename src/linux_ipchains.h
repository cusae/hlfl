#ifndef HLFL_LINUX_IPCHAINS_H__
#define HLFL_LINUX_IPCHAINS_H__

int translate_linux_ipchains(int, char *, char *, char *, char *, char *,
			     char *);
int translate_linux_ipchains_start();
void include_text_ipchains(char *);
#endif
