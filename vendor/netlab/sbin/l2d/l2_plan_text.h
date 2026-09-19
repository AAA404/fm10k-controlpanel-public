#ifndef L2D_PLAN_TEXT_H
#define L2D_PLAN_TEXT_H

#include <stdbool.h>
#include <stddef.h>

bool l2_plan_text_get_str(const char *text, const char *key,
                          char *out, size_t out_size);
int l2_plan_text_validate(const char *text, int *steps,
                          char *err, size_t err_size);

#endif
