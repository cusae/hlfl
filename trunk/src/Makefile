include ../hlfl.tmpl

prefix=/usr/local
OBJS=	bsd_ipfw.o \
	linux_ipchains.o \
	linux_netfilter.o \
	ipfilter.o \
	cisco.o \
	getpts.o \
	utils.o

all : hlfl

cisco.o : cisco.c includes.h config.h hlfl.h ipfilter.h
	$(CC) $(CFLAGS) -c cisco.c
getpts.o : getpts.c includes.h config.h
	$(CC) $(CFLAGS) -c getpts.c

bsd_ipfw.o : bsd_ipfw.c includes.h config.h bsd_ipfw.h
	$(CC) $(CFLAGS) -c bsd_ipfw.c
	
linux_ipchains.o : linux_ipchains.c includes.h config.h hlfl.h linux_ipchains.h
	$(CC) $(CFLAGS) -c linux_ipchains.c

linux_netfilter.o : linux_netfilter.c includes.h config.h hlfl.h linux_netfilter.h
	$(CC) $(CFLAGS) -c linux_netfilter.c

ipfilter.o : ipfilter.c includes.h config.h hlfl.h ipfilter.h
	$(CC) $(CFLAGS) -c ipfilter.c		
	
utils.o : utils.c includes.h config.h
	$(CC) $(CFLAGS) -c utils.c

hlfl : hlfl.c errors.h $(OBJS)
	$(CC) $(CFLAGS) -DVERSION=$(VERSION) hlfl.c $(OBJS) -o hlfl 

install : hlfl
	cp -i hlfl ${prefix}/bin/
	cp -i doc/hlfl.1 ${prefix}/man/man1/
clean :
	rm -f hlfl *.o core *~ config.h
