BUILD ?= release

ifeq ($(BUILD),sanitize)
NETLAB_OPT_CFLAGS ?= -O1
NETLAB_HARDEN_CFLAGS ?= -fno-omit-frame-pointer -fno-common \
	-fsanitize=address,undefined
NETLAB_EXE_LDFLAGS ?= -fsanitize=address,undefined
else ifeq ($(BUILD),debug)
NETLAB_OPT_CFLAGS ?= -O0
NETLAB_HARDEN_CFLAGS ?=
NETLAB_EXE_LDFLAGS ?=
else
NETLAB_OPT_CFLAGS ?= -O2
NETLAB_HARDEN_CFLAGS ?= -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
NETLAB_EXE_LDFLAGS ?= -Wl,-z,relro -Wl,-z,now -pie
endif

NETLAB_BASE_CFLAGS ?= -Wall -Werror -Wextra -pedantic \
	-Wno-error=format-truncation -g \
	$(NETLAB_OPT_CFLAGS) $(NETLAB_HARDEN_CFLAGS)
