CC=gcc
CFLAGS=-I/usr/include/dhcpctl
LDFLAGS=-ldhcpctl -lomapi -ldst -lbsd

dcd: dcd.o
	gcc -o dcd dcd.c $(LDFLAGS)

clean:
	rm -f dcd
	rm -f dcd.o