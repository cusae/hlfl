#ifndef HLFL_LINUX_IPFWADM_H__
#define HLFL_LINUX_IPFWADM_H__

int translate_linux_ipfwadm(int, char *, char *, int, char *, char *, char *,
			    char *);
int translate_linux_ipfwadm_start();
void include_text_ipfwadm(char *);
#endif				/* HLFL_LINUX_IPFWADM_H__ */
