/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "filestore.h"

/* Bytes of the sealed identity blob to show in the sealing illustration. */
#define DUMP_PREFIX 48

/*
 * Build "<dir>/<prefix>[_<hexid>]" into path.  When id is NULL the bare
 * prefix names a singleton (the identity blob).  Returns 0 on success, -1 if
 * the composed path would overflow.
 */
static int
build_path(char *path, size_t cap, const char *dir, const char *prefix,
           int kind, const uint8_t *id, size_t id_len)
{
    char hex[2 * GY_DEVICE_ID_MAX + 1];
    size_t i;

    if (id == NULL) {
        if ((size_t)snprintf(path, cap, "%s/%s", dir, prefix) >= cap)
            return -1;
        return 0;
    }
    if (id_len > GY_DEVICE_ID_MAX)
        return -1;
    for (i = 0; i < id_len; i++)
        snprintf(hex + 2 * i, 3, "%02x", id[i]);
    hex[2 * id_len] = '\0';
    if ((size_t)snprintf(path, cap, "%s/%s_%d_%s", dir, prefix, kind, hex) >=
        cap)
        return -1;
    return 0;
}

/*
 * Read the whole file at path.  Returns GY_OK with *out_len == 0 when the
 * file is absent ("not found"); GY_OK filling out (up to cap) when it fits;
 * and *out_len set to the needed size with GY_ERR_ARG when cap is too small.
 */
static int
read_file(const char *path, uint8_t *out, size_t cap, size_t *out_len)
{
    FILE *f;
    long sz;

    f = fopen(path, "rb");
    if (f == NULL) {
        *out_len = 0;
        return GY_OK;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0) {
        fclose(f);
        return GY_ERR_CRYPTO;
    }
    rewind(f);
    *out_len = (size_t)sz;
    if ((size_t)sz > cap) {
        fclose(f);
        return GY_ERR_ARG;
    }
    if (sz > 0 && fread(out, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        return GY_ERR_CRYPTO;
    }
    fclose(f);
    return GY_OK;
}

/* Write blob to path, replacing any prior contents. */
static int
write_file(const char *path, const uint8_t *blob, size_t blob_len)
{
    FILE *f;

    f = fopen(path, "wb");
    if (f == NULL)
        return GY_ERR_CRYPTO;
    if (blob_len > 0 && fwrite(blob, 1, blob_len, f) != blob_len) {
        fclose(f);
        return GY_ERR_CRYPTO;
    }
    if (fclose(f) != 0)
        return GY_ERR_CRYPTO;
    return GY_OK;
}

static int
cb_load_record(void *ctx, int kind, const uint8_t *id, size_t id_len,
               uint8_t *out, size_t cap, size_t *out_len)
{
    struct filestore *fs = ctx;
    char path[FILESTORE_DIR_MAX + 2 * GY_DEVICE_ID_MAX + 32];

    if (build_path(path, sizeof(path), fs->dir, "rec", kind, id, id_len) != 0)
        return GY_ERR_ARG;
    return read_file(path, out, cap, out_len);
}

static int
cb_store_record(void *ctx, int kind, const uint8_t *id, size_t id_len,
                const uint8_t *blob, size_t blob_len)
{
    struct filestore *fs = ctx;
    char path[FILESTORE_DIR_MAX + 2 * GY_DEVICE_ID_MAX + 32];

    if (build_path(path, sizeof(path), fs->dir, "rec", kind, id, id_len) != 0)
        return GY_ERR_ARG;
    return write_file(path, blob, blob_len);
}

static int
cb_delete_record(void *ctx, int kind, const uint8_t *id, size_t id_len)
{
    struct filestore *fs = ctx;
    char path[FILESTORE_DIR_MAX + 2 * GY_DEVICE_ID_MAX + 32];

    if (build_path(path, sizeof(path), fs->dir, "rec", kind, id, id_len) != 0)
        return GY_ERR_ARG;
    remove(path);
    return GY_OK;
}

static int
cb_load_identity(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    struct filestore *fs = ctx;
    char path[FILESTORE_DIR_MAX + 32];

    if (build_path(path, sizeof(path), fs->dir, "identity", 0, NULL, 0) != 0)
        return GY_ERR_ARG;
    return read_file(path, out, cap, out_len);
}

static int
cb_store_identity(void *ctx, const uint8_t *blob, size_t blob_len)
{
    struct filestore *fs = ctx;
    char path[FILESTORE_DIR_MAX + 32];

    if (build_path(path, sizeof(path), fs->dir, "identity", 0, NULL, 0) != 0)
        return GY_ERR_ARG;
    return write_file(path, blob, blob_len);
}

/*
 * Prekeys are recovered from the sealed identity blob at open, so this store
 * keeps no separate prekey files: report "not found", matching the reference
 * store.
 */
static int
cb_load_prekey(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
               size_t *out_len)
{
    (void)ctx;
    (void)kind;
    (void)pkid;
    (void)out;
    (void)cap;
    *out_len = 0;
    return GY_OK;
}

/*
 * consume_opk marks a one-time prekey used.  The library already zeroizes the
 * consumed OPK inside the re-sealed identity blob it stores right after, so
 * for this file layout there is nothing separate to delete: acknowledge it.
 */
static int
cb_consume_opk(void *ctx, uint32_t pkid)
{
    (void)ctx;
    (void)pkid;
    return GY_OK;
}

int
filestore_bind(struct filestore *fs, const char *dir, gy_store_callbacks *cb)
{
    memset(fs, 0, sizeof(*fs));
    if (strlen(dir) >= sizeof(fs->dir))
        return -1;
    snprintf(fs->dir, sizeof(fs->dir), "%s", dir);

    if (mkdir(dir, 0700) != 0) {
        /* An existing directory (a reopen) is fine. */
        struct stat st;

        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
            return -1;
    }

    cb->ctx = fs;
    cb->load_record = cb_load_record;
    cb->store_record = cb_store_record;
    cb->delete_record = cb_delete_record;
    cb->load_identity = cb_load_identity;
    cb->store_identity = cb_store_identity;
    cb->load_prekey = cb_load_prekey;
    cb->consume_opk = cb_consume_opk;
    return 0;
}

int
filestore_dump_identity(const struct filestore *fs)
{
    uint8_t buf[DUMP_PREFIX];
    char path[FILESTORE_DIR_MAX + 32];
    size_t got, i;
    FILE *f;

    if (build_path(path, sizeof(path), fs->dir, "identity", 0, NULL, 0) != 0)
        return -1;
    f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    got = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    printf("  sealed identity blob at %s (first %zu bytes):\n    ", path, got);
    for (i = 0; i < got; i++)
        printf("%02x", buf[i]);
    printf("\n  this is an opaque seal envelope, not a raw key: a small\n"
           "  cleartext bootstrap header (device uid/did + KEK-wrap blob),\n"
           "  then sealed ciphertext.  private key material never lands here\n"
           "  in the clear.\n");
    return 0;
}
