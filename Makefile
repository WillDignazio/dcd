CC=gcc
CFLAGS=-I/usr/include/dhcpctl
LDFLAGS=-ldhcpctl -lomapi -ldst -lbsd -lmicrohttpd

SRCS =  dcd.c \
	api.c \
	http.c

OBJS = $(SRCS:.c=.o)

.PHONY: clean

dcd: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f dcd
	rm -f *.o