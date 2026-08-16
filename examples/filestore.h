/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * A file-backed gy_store_callbacks implementation over a per-client
 * directory (one file per (kind, id)), so a client's state survives a
 * simulated restart and the sealed-at-rest property is visible on disk.
 * Every blob the library hands a store callback is already library-sealed
 * opaque bytes; this store never sees cleartext key material.
 */

#ifndef GERYON_DEMO_FILESTORE_H
#define GERYON_DEMO_FILESTORE_H

#include "geryon.h"

/* Room for the store directory path. */
#define FILESTORE_DIR_MAX 256

struct filestore {
    char dir[FILESTORE_DIR_MAX];
};

/*
 * Bind fs (over directory dir, created if absent) to a callback table.
 * Returns 0 on success, -1 if the directory cannot be created or the path is
 * too long.
 */
int filestore_bind(struct filestore *fs, const char *dir,
                   gy_store_callbacks *cb);

/*
 * Sealing-at-rest illustration: print a prefix of the sealed
 * identity blob so a reader can SEE it is an opaque seal envelope, not a raw
 * key.  This is an illustration, not a proof: the bootstrap header is
 * deliberately cleartext (device uid/did and the KEK-wrap blob), and public
 * keys inside the sealed body are encrypted only incidentally (they share the
 * struct with the private keys).  The point shown is that PRIVATE material
 * never lands on disk in the clear.  Returns 0 on success, -1 on an I/O error.
 */
int filestore_dump_identity(const struct filestore *fs);

#endif /* GERYON_DEMO_FILESTORE_H */
