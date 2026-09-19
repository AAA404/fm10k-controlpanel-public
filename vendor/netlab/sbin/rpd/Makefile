CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -ll3owner -lconfig -ldaemon -lipc -llog -lpthread
LIBDEPS = ../../build/libipc.a ../../build/libdaemon.a ../../build/libconfig.a \
	../../build/liblog.a ../../build/libl3owner.a

SRCS = main.c switchd_owner_rpc.c rib.c frr_config.c frr_runtime.c \
	frr_telemetry_json.c fpm.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/rpd
TEST_SRCS = $(SRCS) fpm_test_authority.c
TEST_OBJS = $(TEST_SRCS:.c=.test.o)
TEST_DEPS = $(TEST_OBJS:.o=.d)
TEST_TARGET = ../../build/rpd-fpm-test

all: $(TARGET)

test: $(TEST_TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

$(TEST_TARGET): $(TEST_OBJS) $(LIBDEPS)
	$(CC) -o $@ $(TEST_OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

%.test.o: %.c
	$(CC) $(CFLAGS) -DNETLAB_FPM_TEST_AUTHORITY \
		-DNETLAB_FPM_FORCE_PROCFD -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TEST_OBJS) $(TEST_DEPS) \
		$(TARGET) $(TEST_TARGET)
-include $(DEPS) $(TEST_DEPS)
