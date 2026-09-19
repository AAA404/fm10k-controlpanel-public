# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
CC = gcc
include ../../mk/netlab-build.mk
include ../../mk/netlab-deps.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
CFLAGS += $(LYANG_CFLAGS)
LFLAGS = $(NETLAB_EXE_LDFLAGS) -L../../build -lconfig -ldaemon -lipc -llog -lpthread $(LYANG_LIBS)
LIBDEPS = ../../build/libipc.a ../../build/libconfig.a \
          ../../build/libdaemon.a ../../build/liblog.a

SRCS = main.c l2_plan_stage.c l2_intent.c l2_validate.c l2_plan.c l2_fm10k.c \
       l2_hw_probe.c \
       l2_plan_text.c l2d_switchd.c l2d_show.c l2d_cache.c l2d_util.c \
       igmp_snooping.c igmp_state.c
OBJS = $(SRCS:.c=.o) l2_plan_parser.o l2_plan_storage.o
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/l2d

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

l2_plan_parser.o: ../switchd/l2_plan_parser.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

l2_plan_storage.o: ../switchd/l2_plan_storage.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
-include $(DEPS)
