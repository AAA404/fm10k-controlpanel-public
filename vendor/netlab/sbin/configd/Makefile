# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
CC = gcc
include ../../mk/netlab-build.mk
include ../../mk/netlab-deps.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
CFLAGS += $(LYANG_CFLAGS)
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -leventbus -lconfig -ldaemon -lipc -llog -lpthread -lcrypto $(LYANG_LIBS)
LIBDEPS = ../../build/libipc.a ../../build/libeventbus.a \
          ../../build/libconfig.a ../../build/libdaemon.a ../../build/liblog.a

SRCS = main.c l2_client.c l3_client.c switchd_client.c runtime_client.c runtime_scope.c native_runtime.c \
       public_capabilities.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/configd

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
-include $(DEPS)
