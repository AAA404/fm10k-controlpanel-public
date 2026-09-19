#ifndef NETLAB_ERROR_H
#define NETLAB_ERROR_H

#include "types.h"

// Error code categories from L2 backend design spec 16.1
typedef enum {
    NL_ERR_OK = 0,

    // --- CONFIG_ERROR ---
    NL_ERR_INVALID_PATH            = 1001,
    NL_ERR_INVALID_VALUE           = 1002,
    NL_ERR_VLAN_NOT_FOUND          = 1003,
    NL_ERR_VLAN_ID_DUPLICATE       = 1004,
    NL_ERR_INTERFACE_NOT_FOUND     = 1005,
    NL_ERR_INVALID_INTERFACE_MODE  = 1006,
    NL_ERR_ACCESS_MULTIPLE_VLANS   = 1007,
    NL_ERR_NATIVE_VLAN_NOT_IN_TRUNK= 1008,
    NL_ERR_VLAN_REFERENCED         = 1009,
    NL_ERR_UNSUPPORTED_FEATURE     = 1010,
    NL_ERR_VLAN_ID_RANGE           = 1011,
    NL_ERR_VLAN_NAME_INVALID       = 1012,
    NL_ERR_DEFAULT_VLAN_DELETE     = 1013,
    NL_ERR_TRUNK_NO_MEMBERS        = 1014,

    // --- PFE_ERROR ---
    NL_ERR_PFE_DOWN                = 2001,
    NL_ERR_CAPABILITY_INSUFFICIENT = 2002,
    NL_ERR_SDK_INIT_FAILED         = 2003,
    NL_ERR_SDK_CALL_FAILED         = 2004,
    NL_ERR_SDK_TIMEOUT             = 2005,
    NL_ERR_READBACK_MISMATCH       = 2006,
    NL_ERR_HW_STATE_OUT_OF_SYNC    = 2007,

    // --- RPC_ERROR ---
    NL_ERR_RPC_TIMEOUT             = 3001,
    NL_ERR_DAEMON_UNREACHABLE      = 3002,
    NL_ERR_PERMISSION_DENIED       = 3003,
    NL_ERR_TX_ID_REQUIRED          = 3004,
    NL_ERR_IDEMPOTENCY_CONFLICT    = 3005,
    NL_ERR_MALFORMED_REQUEST       = 3006,
    NL_ERR_RPC_BUSY                = 3007,

    // --- ROLLBACK_ERROR ---
    NL_ERR_ROLLBACK_FAILED          = 4001,
    NL_ERR_PRE_STATE_MISSING        = 4002,
    NL_ERR_VERIFY_AFTER_ROLLBACK_FAILED = 4003,

    // --- COMMIT_ERROR ---
    NL_ERR_COMMIT_CONFLICT          = 5001,
    NL_ERR_COMMIT_LOCKED            = 5002,
    NL_ERR_JOURNAL_CORRUPT          = 5003,
} nl_error_code;

// Structured error response (spec 16.2)
typedef struct {
    nl_error_code code;
    const char   *message;
    char          detail[256];
    char          hint[256];
} nl_error_response;

// Get user-friendly error message
const char *nl_error_msg(nl_error_code code);

// Get hint for an error code when applicable
const char *nl_error_hint(nl_error_code code);

// Fill a response with code + detail + hint
void nl_error_fill(nl_error_response *resp, nl_error_code code,
                   const char *detail, const char *hint);

#endif
