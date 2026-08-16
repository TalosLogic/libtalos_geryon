/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "error.h"

const char *
gy_strerror(int code)
{
    switch (code) {
    case GY_OK:
        return "success";
    case GY_ERR_ARG:
        return "bad argument or length";
    case GY_ERR_CRYPTO:
        return "crypto provider failure";
    case GY_ERR_VERIFY:
        return "verification failure";
    case GY_ERR_TOOLONG:
        return "input exceeds length bound";
    case GY_ERR_WEAK_KEY:
        return "weak or degenerate key";
    case GY_ERR_STATE:
        return "invalid state for operation";
    case GY_ERR_UNSUPPORTED:
        return "unsupported feature";
    case GY_ERR_KEY_CHANGED:
        return "peer identity key changed";
    case GY_ERR_EXPIRED:
        return "session expired";
    case GY_ERR_NOT_FOUND:
        return "key handle or id not found";
    case GY_ERR_NO_SPACE:
        return "key-slot table exhausted";
    default:
        return "unknown error";
    }
}
