
CC ?= gcc
AR ?= ar

CFLAGS = -Wall -Wextra -Wpedantic -I. -O3

OBJS = arc4.o sha1.o

.SUFFIXES: .c .o
.PHONY: all clean

all: test-sha1.out test-arc4.out $(OBJS)

test-sha1.out: test-sha1.o sha1.o
	$(CC) $(CFLAGS) -o $@ $^

test-arc4.out: test-arc4.o arc4.o
	$(CC) $(CFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.out

