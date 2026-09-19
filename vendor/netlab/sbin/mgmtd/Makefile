CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -ldaemon -lipc -llog -lpthread
LIBDEPS = ../../build/libipc.a ../../build/libdaemon.a ../../build/liblog.a

SRCS = main.c routes.c backend.c session.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/mgmtd

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
-include $(DEPS)
