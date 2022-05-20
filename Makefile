CC=clang
CFLAGS=-Wall

all: xxh_t01

xxh_t01: xxh_t01.o
	${CC} ${INCLUDE} $^ -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $<

clean:
	rm -f a.out *.o xxh_t01
