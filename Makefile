CC=gcc
CFLAGS=-Wall
INCLUDE=-I/usr/local/include
LDFLAGS=-lxxhash

all: xxh_t01

xxh_t01: xxh_t01.o
	${CC} ${LDFLAGS} $^ -o $@

%.o: %.c
	${CC} ${CFLAGS} ${INCLUDE} -c $<

clean:
	rm -f a.out *.o xxh_t01
