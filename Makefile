
CC ?= gcc
AR ?= ar

CFLAGS = -Wall -Wextra -Wpedantic -I. -O3

.SUFFIXES: .c .o
.PHONY: all clean

all: test-arc4.out test-arc4.o arc4.o

test-arc4.out: test-arc4.o arc4.o
	$(CC) $(CFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.out

