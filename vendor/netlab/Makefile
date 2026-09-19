CC = gcc
include mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE
CFLAGS += -Iinclude
LDFLAGS = $(NETLAB_EXE_LDFLAGS) -lpthread -lrt

LIBDIR = lib
SBINDIR = sbin
BINDIR = bin
BUILDDIR = build
NETLAB_ROOT ?= $(CURDIR)
NETLAB_VENDOR_ROOT ?= /opt/netlab-vendor
NETLAB_SDK_DIR ?= $(NETLAB_VENDOR_ROOT)/fm10000-sdk/ies
PYTHON ?= python3
PYTHON_RUNTIME_LOCK = $(BINDIR)/cli/requirements.lock
VENV ?= .venv
VENV_PYTHON = $(VENV)/bin/python

LIBS = liblog libipc libeventbus libconfig libdaemon libl3owner
DAEMONS = mgmtd configd ifd identityd chassisd packetd stpd lldpd linkmond lacpd l2d rpd statsd

# Detect SDK availability for real switchd build
IES_SDK_DIR ?= $(NETLAB_SDK_DIR)
SDK_LIBS = $(IES_SDK_DIR)/build/libFocalpointSDK.so
SDK_AVAILABLE := $(firstword $(wildcard $(SDK_LIBS)))

.PHONY: all control-plane hardware clean libs daemons cli \
	python-runtime-check check check-surface switchd-real \
	internal-rpc daemon-launch l3-ownerctl rpd-test

all: control-plane

control-plane: libs daemons internal-rpc daemon-launch l3-ownerctl

# === Libraries ===
libs: $(LIBS)

liblog:
	$(MAKE) -C $(LIBDIR)/$@

libipc:
	$(MAKE) -C $(LIBDIR)/$@

libeventbus:
	$(MAKE) -C $(LIBDIR)/$@

libconfig:
	$(MAKE) -C $(LIBDIR)/$@

libdaemon:
	$(MAKE) -C $(LIBDIR)/$@

libl3owner:
	$(MAKE) -C $(LIBDIR)/$@

daemons: $(DAEMONS)

mgmtd: libipc libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

configd: libipc libeventbus libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

ifd: libipc libeventbus libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

identityd: libipc libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

chassisd: libipc libeventbus libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

packetd: libipc libeventbus libconfig liblog
	$(MAKE) -C $(SBINDIR)/$@

stpd: libipc libeventbus libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

lldpd: libipc libeventbus libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

linkmond: libipc libeventbus libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

lacpd: libipc libeventbus libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

l2d: libipc libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

rpd: libipc libconfig libdaemon liblog libl3owner
	$(MAKE) -C $(SBINDIR)/$@

rpd-test: libipc libconfig libdaemon liblog libl3owner
	$(MAKE) -C $(SBINDIR)/rpd test

l3-ownerctl: libipc libconfig liblog libl3owner
	$(MAKE) -C tools/l3-ownerctl

statsd: libipc libconfig libdaemon liblog
	$(MAKE) -C $(SBINDIR)/$@

internal-rpc: libipc liblog
	$(MAKE) -C tools/internal-rpc

daemon-launch: libipc liblog
	$(MAKE) -C tools/daemon-launch

# === Real switchd (optional, user-supplied SDK) ===
hardware: switchd-real

switchd-real: libs
	@if [ -z "$(SDK_AVAILABLE)" ]; then \
		echo "ERROR: an authorized FM10000 SDK is required for hardware builds" >&2; \
		echo "Expected: $(SDK_LIBS)" >&2; \
		echo "Set NETLAB_SDK_DIR=/path/to/authorized-sdk/ies." >&2; \
		exit 1; \
	fi
	$(MAKE) -C $(SBINDIR)/switchd NETLAB_SDK_DIR="$(IES_SDK_DIR)"
	@echo "  switchd-real built with SDK: $(SDK_AVAILABLE)"

# === CLI ===
cli:
	$(PYTHON) -m venv $(VENV)
	$(VENV_PYTHON) -m pip install --require-hashes -r $(PYTHON_RUNTIME_LOCK)

python-runtime-check:
	@$(PYTHON) -c 'import sys; assert sys.version_info >= (3, 11), sys.version'
	@$(PYTHON) -c 'import importlib.metadata as m; expected={"prompt-toolkit":"3.0.52","requests":"2.34.2","wcwidth":"0.8.2","certifi":"2026.6.17","charset-normalizer":"3.4.7","idna":"3.18","urllib3":"2.7.0"}; actual={name:m.version(name) for name in expected}; assert actual == expected, (actual, expected); import prompt_toolkit, requests, wcwidth, certifi, charset_normalizer, idna, urllib3'

check: python-runtime-check check-surface
	$(PYTHON) -B -m compileall -q bin scripts tests
	$(PYTHON) -B scripts/run-public-tests.py

check-surface:
	$(PYTHON) -B scripts/check-public-surface.py

# === Clean ===
clean:
	rm -rf $(BUILDDIR)
	for lib in $(LIBS); do $(MAKE) -C $(LIBDIR)/$$lib clean; done
	for dmn in $(DAEMONS); do $(MAKE) -C $(SBINDIR)/$$dmn clean; done
	$(MAKE) -C tools/internal-rpc clean
	$(MAKE) -C tools/daemon-launch clean
	$(MAKE) -C tools/l3-ownerctl clean
