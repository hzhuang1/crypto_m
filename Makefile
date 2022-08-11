CC=gcc
CFLAGS=-Wall
INCLUDE=-I/usr/local/include
LDFLAGS=-lxxhash

all: xxh_t01 xxh_t02 a_sve_t01

xxh_t01: xxh_t01.o
	${CC} ${LDFLAGS} $^ -o $@

xxh_t02: xxh_t02.o
	${CC} ${LDFLAGS} $^ -o $@

a_sve_t01: a_sve_t01.o sve_t01.o sve_t02.o
	${CC} ${LDFLAGS} $^ -o $@

%.o: %.c
	${CC} ${CFLAGS} ${INCLUDE} -c $<

sve_t01.o: sve_t01.S
	as $^ -o $@

sve_t02.o: sve_t02.S
	as $^ -o $@

clean:
	rm -f a.out *.o xxh_t01 xxh_t02 a_sve_t01
