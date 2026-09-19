#ifndef FM10K_EYE_FIRMWARE_H
#define FM10K_EYE_FIRMWARE_H
#include <stdint.h>
#define FM10K_EYE_MASTER_WORDS 4968
#define FM10K_EYE_MASTER_VERSION UINT32_C(0x101a0001)
#define FM10K_EYE_MASTER_PATH "/opt/fm10k-controlpanel/native/hardware/eye/sbus-master-101a.bin"
/* A separately supplied, root-owned image; never received through Web/RPC. */
int fm10k_eye_firmware_read(const char *, uint16_t out[FM10K_EYE_MASTER_WORDS]);
#endif
