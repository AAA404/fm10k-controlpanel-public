# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -leventbus -lconfig -ldaemon -lipc -llog -lpthread -lcrypto
LIBDEPS = ../../build/libdaemon.a ../../build/libipc.a \
          ../../build/libeventbus.a ../../build/libconfig.a ../../build/liblog.a

SRCS = main.c stp_wire.c stp_lag.c stp_config_text.c stp_packet_io.c stp_switchd.c stp_show.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/stpd

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
-include $(DEPS)
