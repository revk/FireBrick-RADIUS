SQLINC=$(shell mysql_config --include)
SQLLIB=$(shell mysql_config --libs)
SQLVER=$(shell mysql_config --version | sed 'sx\..*xx')
CCOPTS=${SQLINC} -I. -I/usr/local/ssl/include -ISQLlib -D_GNU_SOURCE -g -Wall -funsigned-char
OPTS=-L/usr/local/ssl/lib ${SQLLIB} ${CCOPTS}

all: fb-radius-auth fb-radius-acct fb-radius-msg

update:
	git submodule update --remote --merge

SQLlib/sqllib.o: SQLlib/sqllib.c
	make -C SQLlib

fb-radius-auth: fb-radius-auth.c SQLlib/sqllib.o
	cc -O -o $@ $< ${OPTS} -lm -lpopt -lcrypto SQLlib/sqllib.o

fb-radius-acct: fb-radius-acct.c SQLlib/sqllib.o
	cc -O -o $@ $< ${OPTS} -lm -lpopt -lcrypto SQLlib/sqllib.o

fb-radius-msg: fb-radius-msg.c
	cc -O -o $@ $< ${OPTS} -lm -lpopt -lcrypto
