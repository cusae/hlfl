#ifndef HLFL_UTILS_H
#define HLFL_UTILS_H

char *matching_items(char *, char, char);
char *strchr_items(char *, char, char, char);

#ifndef HAVE_INET_ATON
int inet_aton(register const char *, struct in_addr *);
#endif				/* ! HAVE_INET_ATON */

#endif				/* HLFL_UTILS_H */
