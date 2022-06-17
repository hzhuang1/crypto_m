CC=gcc
CFLAGS=-Wall
INCLUDE=-I/usr/local/include
LDFLAGS=-lxxhash

all: xxh_t01 a_sve_t01

xxh_t01: xxh_t01.o
	${CC} ${LDFLAGS} $^ -o $@

a_sve_t01: a_sve_t01.o sve_t01.o
	${CC} ${LDFLAGS} $^ -o $@

%.o: %.c
	${CC} ${CFLAGS} ${INCLUDE} -c $<

sve_t01.o: sve_t01.S
	as $^ -o $@

clean:
	rm -f a.out *.o xxh_t01 a_sve_t01
