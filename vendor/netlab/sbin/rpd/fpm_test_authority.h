#ifndef RPD_FPM_TEST_AUTHORITY_H
#define RPD_FPM_TEST_AUTHORITY_H

#include "fpm.h"

int rpd_fpm_test_authority_snapshot(
    rpd_fpm_peer_authority *authority, char *err, size_t err_size);

#endif
