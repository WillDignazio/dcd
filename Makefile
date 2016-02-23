CC=clang
CFLAGS=-ggdb -O0 -Wall -Wextra -Werror -I/usr/include/dhcpctl $(shell pkg-config --cflags glib)
LDFLAGS=-ldhcpctl -lomapi -ldst -lbsd -lmicrohttpd -lglib -ljansson

SRCS =  dcd.c \
	api.c \
	http.c \
	routes.c

OBJS = $(SRCS:.c=.o)

.PHONY: clean

dcd: $(OBJS) dcd.h
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
clean:
	rm -f dcd
	rm -f *.o