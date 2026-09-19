CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -leventbus -lconfig -ldaemon -lipc -llog -lpthread
LIBDEPS = ../../build/libdaemon.a ../../build/libipc.a \
          ../../build/libeventbus.a ../../build/libconfig.a ../../build/liblog.a

SRCS = main.c lacp_packet_io.c lacp_wire.c lacp_config.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/lacpd

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
-include $(DEPS)
