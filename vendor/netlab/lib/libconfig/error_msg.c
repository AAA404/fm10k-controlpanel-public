#include "netlab/error.h"
#include <string.h>
#include <stdio.h>

const char *nl_error_msg(nl_error_code code) {
    switch (code) {
    case NL_ERR_OK:                     return "OK";
    // CONFIG_ERROR
    case NL_ERR_INVALID_PATH:           return "invalid configuration path";
    case NL_ERR_INVALID_VALUE:          return "invalid value for this configuration key";
    case NL_ERR_VLAN_NOT_FOUND:         return "VLAN is not defined";
    case NL_ERR_VLAN_ID_DUPLICATE:      return "vlan-id already used by another VLAN";
    case NL_ERR_INTERFACE_NOT_FOUND:    return "interface not found";
    case NL_ERR_INVALID_INTERFACE_MODE: return "invalid interface-mode (must be access or trunk)";
    case NL_ERR_ACCESS_MULTIPLE_VLANS:  return "access interface requires exactly one VLAN member";
    case NL_ERR_NATIVE_VLAN_NOT_IN_TRUNK: return "native-vlan-id must be included in trunk vlan members";
    case NL_ERR_VLAN_REFERENCED:        return "VLAN is still referenced by interfaces";
    case NL_ERR_UNSUPPORTED_FEATURE:    return "feature is not supported in this build";
    case NL_ERR_VLAN_ID_RANGE:          return "vlan-id must be in range 1..4094";
    case NL_ERR_VLAN_NAME_INVALID:      return "invalid VLAN name";
    case NL_ERR_DEFAULT_VLAN_DELETE:    return "cannot delete default VLAN";
    case NL_ERR_TRUNK_NO_MEMBERS:       return "trunk interface has no VLAN members";
    // PFE_ERROR
    case NL_ERR_PFE_DOWN:               return "commit rejected: PFE is down";
    case NL_ERR_CAPABILITY_INSUFFICIENT: return "PFE capability insufficient for this commit";
    case NL_ERR_SDK_INIT_FAILED:        return "SDK initialization failed";
    case NL_ERR_SDK_CALL_FAILED:        return "SDK call failed";
    case NL_ERR_SDK_TIMEOUT:            return "SDK call timed out";
    case NL_ERR_READBACK_MISMATCH:      return "hardware read-back verification failed";
    case NL_ERR_HW_STATE_OUT_OF_SYNC:    return "hardware state is out of sync";
    // RPC_ERROR
    case NL_ERR_RPC_TIMEOUT:            return "daemon RPC timed out";
    case NL_ERR_DAEMON_UNREACHABLE:     return "daemon is unreachable";
    case NL_ERR_PERMISSION_DENIED:      return "permission denied";
    case NL_ERR_TX_ID_REQUIRED:         return "transaction ID is required for this operation";
    case NL_ERR_IDEMPOTENCY_CONFLICT:   return "idempotency conflict: parameters differ from cached result";
    case NL_ERR_MALFORMED_REQUEST:      return "malformed request";
    case NL_ERR_RPC_BUSY:               return "daemon RPC resource is busy";
    // ROLLBACK_ERROR
    case NL_ERR_ROLLBACK_FAILED:        return "rollback failed";
    case NL_ERR_PRE_STATE_MISSING:      return "pre-state missing for rollback";
    case NL_ERR_VERIFY_AFTER_ROLLBACK_FAILED: return "hardware verification failed after rollback";
    // COMMIT_ERROR
    case NL_ERR_COMMIT_CONFLICT:        return "active configuration changed since this session started";
    case NL_ERR_COMMIT_LOCKED:          return "commit lock is held by another session";
    case NL_ERR_JOURNAL_CORRUPT:        return "commit journal is corrupt";
    default:                            return "unknown error";
    }
}

const char *nl_error_hint(nl_error_code code) {
    switch (code) {
    case NL_ERR_INTERFACE_NOT_FOUND:
        return "run \"show interfaces terse\" to list available interfaces";
    case NL_ERR_VLAN_NOT_FOUND:
        return "configure it with \"set vlans <name> vlan-id <1-4094>\"";
    case NL_ERR_VLAN_REFERENCED:
        return "remove interface memberships before deleting this VLAN";
    case NL_ERR_HW_STATE_OUT_OF_SYNC:
        return "run \"show system alarms\" and \"request system reconcile\"";
    case NL_ERR_PFE_DOWN:
        return "run \"show chassis forwarding\" for PFE status details";
    case NL_ERR_COMMIT_CONFLICT:
        return "update candidate configuration before commit";
    case NL_ERR_UNSUPPORTED_FEATURE:
        return "this feature is outside the current hardware-backed command set";
    case NL_ERR_RPC_BUSY:
        return "retry the request after a short delay";
    default:
        return NULL;
    }
}

void nl_error_fill(nl_error_response *resp, nl_error_code code,
                   const char *detail, const char *hint) {
    resp->code = code;
    resp->message = nl_error_msg(code);
    resp->detail[0] = '\0';
    resp->hint[0]   = '\0';
    if (detail) {
        snprintf(resp->detail, sizeof(resp->detail), "%s", detail);
    }
    if (hint) {
        snprintf(resp->hint, sizeof(resp->hint), "%s", hint);
    } else {
        const char *h = nl_error_hint(code);
        if (h) {
            snprintf(resp->hint, sizeof(resp->hint), "%s", h);
        }
    }
}
