CC = gcc
include ../../mk/netlab-build.mk
include ../../mk/netlab-deps.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
CFLAGS += $(LYANG_CFLAGS)
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -lconfig -ldaemon -lipc -llog -lpthread $(LYANG_LIBS)
LIBDEPS = ../../build/libipc.a ../../build/libconfig.a \
          ../../build/libdaemon.a ../../build/liblog.a

SRCS = main.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/ifd

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
-include $(DEPS)
