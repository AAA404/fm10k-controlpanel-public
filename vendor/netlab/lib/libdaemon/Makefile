CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS) -fPIC
CFLAGS += -D_GNU_SOURCE -I../../include
LDFLAGS = -lpthread

SRCS = daemon.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
LIB = ../../build/libdaemon.a

all: $(LIB)

$(LIB): $(OBJS)
	@mkdir -p ../../build
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
-include $(DEPS)
