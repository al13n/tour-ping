CC=gcc

HOME=/users/cse533/Stevens/unpv13e

LIBS = -lpthread ${HOME}/libunp.a -lm -lc
FLAGS = -g3

CFLAGS = ${FLAGS} -I${HOME}/lib

all: tour_apoddar arp_apoddar

tour_apoddar: tour-test.o api.o ping.o get_hw_addrs.o
		${CC} ${FLAGS} -o $@ $^ ${LIBS}

tour-test.o: tour-test.c
	${CC} ${CFLAGS} -c -o $@ $^


arp_apoddar: arp.o get_hw_addrs.o api.o
		${CC} ${FLAGS} -o $@ $^ ${LIBS}

arp.o: arp.c
	${CC} ${CFLAGS} -c -o $@ $^


api.o: api.c
	${CC} ${CFLAGS} -c -o $@ $^

get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c -o $@ $^

ping.o: pg.c
	${CC} ${CFLAGS} -c -o $@ $^	

clean:
	rm *.o


