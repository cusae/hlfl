#ifndef HLFL_LINUX_netfilter_H__
#define HLFL_LINUX_netfilter_H__

int translate_linux_netfilter(int, char*, char*, char*, char*, char*, char*);
int translate_linux_netfilter_start();
void include_text_netfilter(char*);
#endif
