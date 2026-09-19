# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
CC = gcc
include ../../mk/netlab-build.mk

CFLAGS = -std=c11 $(NETLAB_BASE_CFLAGS)
CFLAGS += -D_GNU_SOURCE -I../../include
FM10K_NATIVE_DIR ?= $(abspath ../../../../hardware/native)
CFLAGS += -I$(FM10K_NATIVE_DIR)
NETLAB_ROOT ?= $(abspath ../..)
NETLAB_SDK_DIR ?= /opt/netlab-vendor/fm10000-sdk/ies
IES_SDK ?= $(NETLAB_SDK_DIR)
CFLAGS += -I$(IES_SDK)/include \
          -I$(IES_SDK)/include/platforms \
          -I$(IES_SDK)/include/alos \
          -I$(IES_SDK)/include/alos/linux \
          -I$(IES_SDK)/include/common \
          -I$(IES_SDK)/include/api \
          -I$(IES_SDK)/include/std/intel \
          -I$(IES_SDK)/include/platforms/libertyTrail \
          -I$(IES_SDK)/include/platforms/common \
          -I$(IES_SDK)/include/platforms/util/boardManager
LFLAGS = $(NETLAB_EXE_LDFLAGS) -rdynamic -L../../build -leventbus -lconfig -ldaemon -lipc -llog
# SDK math imports must precede libm when Debian links with --as-needed.
LFLAGS += -L$(IES_SDK)/build -lFocalpointSDK -Wl,--allow-multiple-definition -lpthread -lrt -lm -ldl
LIBDEPS = ../../build/libipc.a ../../build/libeventbus.a \
          ../../build/libdaemon.a \
          ../../build/libconfig.a ../../build/liblog.a

SRCS = main.c sdk_init.c sdk_executor.c sdk_event_handler.c fm10k_board_sdk.c fm10k_board_runtime.c fm10k_startup.c fm10k_basic100g.c fm10k_phy.c fm10k_eye.c \
       sdk_event_barrier.c \
       sflow_capture.c hal_sflow.c \
       commit_finalizer.c hw_state_tracker.c read_back_verifier.c \
       hal_port.c hal_port_xcvr_sdk_adapter.c \
       hal_vlan.c hal_l3.c hal_counters.c \
       hal_xcvr.c hal_chassis.c l2_plan_storage.c l2_plan_parser.c \
       l3_plan_parser.c hal_config.c \
       hal_packet.c hal_lag.c fm10k_lag.c \
       hal_resources.c hal_switch_config.c hal_flow_table.c hal_acl_resource.c \
       hal_control_plane.c hal_cpu_protection.c hal_multicast.c hal_acl_policer_probe.c \
       hal_storm_control.c hal_egress_rate_limit.c hal_qos.c hal_pfc_watchdog.c \
       hal_mirror.c hal_acl_counter_snapshot.c \
       hal_l2_security.c hal_ingress_ipv4_acl.c hal_sdk_runtime.c \
       rpc_format.c rpc_response.c rpc_server.c pfe_capability.c
OBJS = $(SRCS:.c=.o) fm10k_board_core.o fm10k_monitor_core.o fm10k_eye_scan_core.o fm10k_eye_firmware_core.o fm10k_pfc_watchdog_core.o
DEPS = $(OBJS:.o=.d)
TARGET = ../../build/switchd

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBDEPS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

fm10k_board_core.o: $(FM10K_NATIVE_DIR)/fm10k_board.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

fm10k_monitor_core.o: $(FM10K_NATIVE_DIR)/fm10k_monitor.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

fm10k_eye_scan_core.o: $(FM10K_NATIVE_DIR)/fm10k_eye_scan.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

fm10k_eye_firmware_core.o: $(FM10K_NATIVE_DIR)/fm10k_eye_firmware.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

fm10k_pfc_watchdog_core.o: $(FM10K_NATIVE_DIR)/fm10k_pfc_watchdog.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
-include $(DEPS)
