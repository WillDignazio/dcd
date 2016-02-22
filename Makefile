CC=clang
CFLAGS=-ggdb -O0 -Wall -Wextra -Werror -I/usr/include/dhcpctl $(shell pkg-config --cflags glib)
LDFLAGS=-ldhcpctl -lomapi -ldst -lbsd -lmicrohttpd -lprotobuf-c -lglib -luuid

SRCS =  dcd.c \
	api.c \
	http.c \
	routes.c

OBJS = $(SRCS:.c=.o)

.PHONY: clean proto

dcd: proto $(OBJS) dcd.h
	$(CC) $(CFLAGS) -o $@ $(OBJS) api.pb-c.c $(LDFLAGS)

proto:
	protoc-c --c_out=. api.proto

clean:
	rm -f dcd
	rm -f *.o