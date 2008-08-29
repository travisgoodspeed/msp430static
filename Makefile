
install:
	ln -s `pwd`/msp430static.pl /usr/local/bin/msp430static
	ln -s `pwd`/msp430static.pl /usr/local/bin/m4s
uninstall:
	rm -f /usr/local/bin/msp430static /usr/local/bin/m4s
#init:
#	rm -f 430static.db
#	./msp430static.pl init <tests/tinyos/blink.exe.ss
#	./msp430static.pl .lib.import.gnu
#	./msp430static.pl .lib.import.tinyos
#	./msp430static.pl index
#reload:
#	./msp430static.pl reload <tests/tinyos/blink.exe.ss


#pmods_cpan:
#	perl -MCPAN -e 'install DBI'
pmods_ubuntu:
	apt-get install libdbi-perl libdbd-sqlite3-perl libgd-gd2-perl