/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "demo_ipc.h"

/*
 * Write len bytes in full, retrying short writes and EINTR.  Returns 0 on
 * success, -1 on a hard error.
 */
static int
write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/*
 * Read len bytes in full.  Returns DEMO_IPC_OK on success, DEMO_IPC_EOF if
 * the peer closes before any byte of this chunk arrives (a clean frame
 * boundary), and DEMO_IPC_ERR on a hard error or a truncated frame.
 */
static int
read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return DEMO_IPC_ERR;
        }
        if (n == 0)
            return off == 0 ? DEMO_IPC_EOF : DEMO_IPC_ERR;
        off += (size_t)n;
    }
    return DEMO_IPC_OK;
}

int
demo_send_frame(int fd, const struct demo_frame_header *hdr,
                const uint8_t *data)
{
    if (hdr == NULL)
        return DEMO_IPC_ERR;
    if (hdr->data_len > DEMO_MAX_PAYLOAD)
        return DEMO_IPC_ERR;
    if (hdr->data_len > 0 && data == NULL)
        return DEMO_IPC_ERR;

    if (write_full(fd, hdr, sizeof(*hdr)) != 0)
        return DEMO_IPC_ERR;
    if (hdr->data_len > 0 && write_full(fd, data, hdr->data_len) != 0)
        return DEMO_IPC_ERR;
    return DEMO_IPC_OK;
}

int
demo_recv_frame(int fd, struct demo_frame_header *hdr, uint8_t *buf, size_t cap)
{
    int rv;

    if (hdr == NULL)
        return DEMO_IPC_ERR;

    rv = read_full(fd, hdr, sizeof(*hdr));
    if (rv != DEMO_IPC_OK)
        return rv;

    if (hdr->data_len > DEMO_MAX_PAYLOAD || hdr->data_len > cap)
        return DEMO_IPC_ERR;

    if (hdr->data_len > 0) {
        if (buf == NULL)
            return DEMO_IPC_ERR;
        rv = read_full(fd, buf, hdr->data_len);
        if (rv != DEMO_IPC_OK)
            return rv == DEMO_IPC_EOF ? DEMO_IPC_ERR : rv;
    }
    return DEMO_IPC_OK;
}
