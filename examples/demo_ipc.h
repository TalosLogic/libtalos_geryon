/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Length-framed pipe IPC for the geryon example.  Every read and write is
 * looped to completion (a pipe read or write can be short, and either can be
 * interrupted by a signal), so a frame is delivered whole or not at all.
 */

#ifndef GERYON_DEMO_IPC_H
#define GERYON_DEMO_IPC_H

#include <stddef.h>
#include <stdint.h>

#include "demo_proto.h"

/* Outcome of a framed read.  A write returns only OK or ERR. */
enum demo_ipc_result {
    DEMO_IPC_OK = 0,  /* a full frame was transferred */
    DEMO_IPC_EOF = 1, /* the peer closed its end before/between frames */
    DEMO_IPC_ERR = -1 /* an I/O error, or a frame that broke the contract */
};

/*
 * Send one frame: the header, then hdr->data_len payload bytes.  data may be
 * NULL only when hdr->data_len is 0.  Returns DEMO_IPC_OK or DEMO_IPC_ERR.
 */
int demo_send_frame(int fd, const struct demo_frame_header *hdr,
                    const uint8_t *data);

/*
 * Receive one frame into caller storage.  hdr is always filled on OK; the
 * payload is read into buf, which must be at least cap bytes.  A payload
 * larger than cap (or larger than DEMO_MAX_PAYLOAD) is a contract violation
 * and returns DEMO_IPC_ERR.  A clean peer close returns DEMO_IPC_EOF.
 */
int demo_recv_frame(int fd, struct demo_frame_header *hdr, uint8_t *buf,
                    size_t cap);

#endif /* GERYON_DEMO_IPC_H */
