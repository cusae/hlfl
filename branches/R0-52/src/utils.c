#include "includes.h"



char *
strchr_items(str, chr, open, close)
 char *str;
 char chr, open, close;
{
 while (str[0])
   {
    if (str[0] == chr)
     return str;

    else if (str[0] == open)
      {
       str = strchr(str + 1, close);
       if (!str)
	return str;
      }
    str++;
   }
 if (!str[0])
  str = NULL;
 return str;
}

char *
matching_items(str, open, close)
 char *str;
 char open;
 char close;
{

 char *s = (char *) strchr(str, open);
 if (s)
   {
    char v;
    int level = 1;
    while (level)
      {
       s++;
       v = s[0];
       if (!v)
	break;
       if (v == open)
	level++;
       else if (v == close)
	level--;
      }
    if (!s[0])
     s = NULL;
   }
 return s;
}
