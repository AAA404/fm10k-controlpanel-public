# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS) -fPIC
CFLAGS += -D_GNU_SOURCE -I../../include
LDFLAGS = -lpthread

SRCS = port_scope.c ipc.c ipc_contract.c rpc_client.c daemon_identity.c \
       process_identity.c identity_broker.c l2_plan_build.c \
       mac_snapshot.c stp_snapshot.c \
       acl_counter_snapshot.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
LIB = ../../build/libipc.a

all: $(LIB)

$(LIB): $(OBJS)
	@mkdir -p ../../build
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
-include $(DEPS)
