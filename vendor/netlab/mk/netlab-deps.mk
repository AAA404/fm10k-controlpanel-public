# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
# Public dependency discovery shared by libyang consumers.
#
# Distribution packages normally expose libyang v2 through pkg-config. A
# source or private installation can instead set NETLAB_LIBYANG_PREFIX.
NETLAB_LIBYANG_PREFIX ?=

ifneq ($(strip $(NETLAB_LIBYANG_PREFIX)),)
LYANG_CFLAGS ?= -I$(NETLAB_LIBYANG_PREFIX)/include
NETLAB_LIBYANG_LIBDIR := $(if $(wildcard $(NETLAB_LIBYANG_PREFIX)/lib/libyang.so),$(NETLAB_LIBYANG_PREFIX)/lib,$(NETLAB_LIBYANG_PREFIX)/lib64)
LYANG_LIBS ?= -L$(NETLAB_LIBYANG_LIBDIR) -lyang
else
LYANG_CFLAGS ?= $(shell pkg-config --cflags 'libyang >= 2.0' 'libyang < 3.0' 2>/dev/null)
LYANG_LIBS ?= $(shell pkg-config --libs 'libyang >= 2.0' 'libyang < 3.0' 2>/dev/null)
endif
