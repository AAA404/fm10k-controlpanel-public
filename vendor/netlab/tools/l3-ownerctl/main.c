#include "netlab/ipc.h"
#include "netlab/l3_owner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OWNER_TX_MAX 65536

static char *read_file(const char *path, char *error, size_t error_size) {
    FILE *file;
    char *text;
    long length;

    file = fopen(path, "rb");
    if (!file) {
        snprintf(error, error_size, "open failed: %s", path);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0 ||
        (length = ftell(file)) < 0 || length > NETLAB_MAX_MSG) {
        fclose(file);
        snprintf(error, error_size, "invalid file size: %s", path);
        return NULL;
    }
    rewind(file);
    text = calloc(1, (size_t)length + 1);
    if (!text) {
        fclose(file);
        snprintf(error, error_size, "out of memory");
        return NULL;
    }
    if (length > 0 &&
        fread(text, 1, (size_t)length, file) != (size_t)length) {
        free(text);
        fclose(file);
        snprintf(error, error_size, "read failed: %s", path);
        return NULL;
    }
    fclose(file);
    return text;
}

static int validate_file(const char *path) {
    char error[256] = {0};
    char summary[160] = {0};
    char *text = read_file(path, error, sizeof(error));

    if (!text || nl_l3_owner_plan_validate(
            text, summary, sizeof(summary), error, sizeof(error)) != 0) {
        fprintf(stderr, "error: persistent L3 owner plan invalid: %s\n",
                error[0] ? error : "unknown error");
        free(text);
        return 1;
    }
    free(text);
    printf("l3-ownerctl validate ok %s\n", summary);
    return 0;
}

static int compile_file(const char *path) {
    char error[256] = {0};
    char transaction[OWNER_TX_MAX];
    char *text = read_file(path, error, sizeof(error));

    if (!text || nl_l3_owner_plan_compile(
            text, transaction, sizeof(transaction),
            error, sizeof(error)) != 0) {
        fprintf(stderr, "error: persistent L3 owner plan invalid: %s\n",
                error[0] ? error : "unknown error");
        free(text);
        return 1;
    }
    free(text);
    fputs(transaction, stdout);
    return 0;
}

static int resource_check_file(const char *path, const char *profile_path,
                               bool apply_dry_run) {
    nl_l3_owner_options options = {
        .authority_name = "rpd",
        .public_reason =
            "public routing config commits through configd and rpd persistent owner",
        .switchd_caller_daemon = NL_DAEMON_RPD,
    };
    char error[256] = {0};
    char xml[4096] = {0};
    char *text = read_file(path, error, sizeof(error));
    nl_l3_owner *owner = nl_l3_owner_create(&options);
    int rc;

    if (!text || !owner) {
        fprintf(stderr, "error: %s\n",
                error[0] ? error : "cannot create persistent L3 owner");
        free(text);
        nl_l3_owner_destroy(owner);
        return 1;
    }
    rc = nl_l3_owner_plan_resource_check(
        owner, text, profile_path, xml, sizeof(xml),
        error, sizeof(error));
    free(text);
    nl_l3_owner_destroy(owner);
    if (rc != 0) {
        puts(xml);
        fprintf(stderr, "error: L3 owner resource check failed: %s\n",
                error[0] ? error : "unknown error");
        return 1;
    }
    if (apply_dry_run)
        printf("<l3-owner-apply-dry-run status=\"ok\" "
               "hardware-apply=\"disabled\" rollback=\"available\">"
               "%s</l3-owner-apply-dry-run>\n", xml);
    else
        puts(xml);
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s --validate-file PLAN | --compile-file PLAN | "
            "--resource-check-file PLAN [--profile PROFILE] | "
            "--apply-dry-run-file PLAN [--profile PROFILE]\n",
            program);
}

int main(int argc, char **argv) {
    const char *profile = NULL;

    if (argc == 3 && strcmp(argv[1], "--validate-file") == 0)
        return validate_file(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--compile-file") == 0)
        return compile_file(argv[2]);
    if (argc == 5 && strcmp(argv[3], "--profile") == 0)
        profile = argv[4];
    if ((argc == 3 || argc == 5) &&
        strcmp(argv[1], "--resource-check-file") == 0)
        return resource_check_file(argv[2], profile, false);
    if ((argc == 3 || argc == 5) &&
        strcmp(argv[1], "--apply-dry-run-file") == 0)
        return resource_check_file(argv[2], profile, true);
    usage(argv[0]);
    return 2;
}
