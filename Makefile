include hlfl.tmpl

all : hlfl.tmpl
	cd src && make

hlfl.tmpl :
	./configure

src/hlfl :
	cd src && make

install : src/hlfl
	@test -d ${bindir} || $(INSTALL) -c -d ${bindir}
	$(INSTALL) -m 0755 -o root src/hlfl ${bindir}
	@test -d ${mandir}/man1 || $(INSTALL) -c -d ${mandir}/man1
	$(INSTALL) -m 0444 -o root doc/hlfl.1 ${mandir}/man1/
	@test -d ${datadir}/hlfl || $(INSTALL) -c -d ${datadir}/hlfl
	$(INSTALL) -m 0444 -o root doc/services.hlfl ${datadir}/hlfl
	$(INSTALL) -m 0444 -o root doc/sample_1.hlfl ${datadir}/hlfl
	$(INSTALL) -m 0444 -o root doc/sample_2.hlfl ${datadir}/hlfl
	$(INSTALL) -m 0444 -o root doc/test.hlfl ${datadir}/hlfl
	$(INSTALL) -m 0444 -o root doc/syntax.txt ${datadir}/hlfl

uninstall :
	rm -rf ${bindir}/hlfl
	rm -f ${mandir}/man1/hlfl.1
	rm -rf ${datadir}/hlfl

clean :
	cd src && make clean

distclean : clean
	rm -f config.cache config.status config.log hlfl.tmpl src/config.h

release : distclean
	echo `cat VERSION`
	rm -rf ChangeLog /tmp/hlfl-`cat VERSION`.tar* ../hlfl-`cat VERSION`
	rcs2log -v -u "asl:Arnaud Launay:launay@hlfl.org" -u "renaud:Renaud Deraison:deraison@hlfl.org" * >ChangeLog
	cp -a ../hlfl ../hlfl-`cat VERSION`
	tar cvf /tmp/hlfl-`cat VERSION`.tar -C .. hlfl-`cat VERSION`
	bzip2 -9 -k /tmp/hlfl-`cat VERSION`.tar
	gzip -9 /tmp/hlfl-`cat VERSION`.tar
