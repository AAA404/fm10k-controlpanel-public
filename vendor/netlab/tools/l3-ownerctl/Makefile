CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -ll3owner -lipc -lconfig -llog -lpthread
LIBDEPS = ../../build/libl3owner.a ../../build/libipc.a \
	../../build/libconfig.a ../../build/liblog.a

SRCS = main.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/l3-ownerctl

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

-include $(DEPS)
