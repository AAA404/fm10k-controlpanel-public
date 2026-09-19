CC = gcc
include ../../mk/netlab-build.mk
include ../../mk/netlab-deps.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS) -fPIC
CFLAGS += -D_GNU_SOURCE -I../../include
LDFLAGS =

SRCS = commit_journal.c session.c interface_id.c error_msg.c yang_config.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
LIB = ../../build/libconfig.a

all: $(LIB)

$(LIB): $(OBJS)
	@mkdir -p ../../build
	ar rcs $@ $^

yang_config.o: yang_config.c
	$(CC) $(CFLAGS) $(LYANG_CFLAGS) -MMD -MP -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
-include $(DEPS)
