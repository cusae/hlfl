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

cisco.o : cisco.c
	$(CC) $(CFLAGS) -c cisco.c
getpts.o : getpts.c 
	$(CC) $(CFLAGS) -c getpts.c

bsd_ipfw.o : bsd_ipfw.c
	$(CC) $(CFLAGS) -c bsd_ipfw.c
	
linux_ipchains.o : linux_ipchains.c
	$(CC) $(CFLAGS) -c linux_ipchains.c

linux_netfilter.o : linux_netfilter.c
	$(CC) $(CFLAGS) -c linux_netfilter.c

checkpoint.o : checkpoint.c
	$(CC) $(CFLAGS) -c checkpoint.c
	
		
ipfilter.o : ipfilter.c
	$(CC) $(CFLAGS) -c ipfilter.c		
	
utils.o : utils.c
	$(CC) $(CFLAGS) -c utils.c

hlfl : hlfl.c errors.h $(OBJS)
	$(CC) $(CFLAGS) -DVERSION=$(VERSION) hlfl.c $(OBJS) -static -o hlfl 

install : hlfl
	cp -i hlfl ${prefix}/bin/
	cp -i doc/hlfl.1 ${prefix}/man/man1/
clean :
	rm -f hlfl *.o core
