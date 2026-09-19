CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -lipc -llog -lpthread
LIBDEPS = ../../build/libipc.a ../../build/liblog.a

SRCS = main.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/netlab-daemon-launch

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)
	chmod 0755 $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

-include $(DEPS)
