/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon_group_server.h - public server API for the classical private group
 * system (GROUP_SPEC section 8, [CPZ] ePrint 2019/1416).  A SEPARATE,
 * STATELESS target (geryon_groups_server) holding only the group service's
 * KVAC key (ServerSecretParams).  It carries NO user identity, NO prekeys, NO
 * sessions, and NO messaging: it never sees a custodian.  A client never links
 * it, and this header deliberately depends on NOTHING in geryon.h, so the
 * client/server boundary (GROUP_SPEC section 8) is an ABI property, not only a
 * symbol-audit one.
 *
 * STATELESSNESS (section 8.2): the handle holds only the sealed server key.
 * Every operation is a pure function of its inputs and that key.  The group's
 * membership, the encrypted member list, and all other group state belong to
 * the deploying server; this target verifies and issues, it does not store.
 *
 * WIRE OBJECTS ARE OPAQUE.  Requests and presentations arrive as the canonical
 * byte strings the client produced; issuance responses and the extracted
 * ciphertexts leave as canonical byte strings.  The (uint8_t *out, size_t
 * *out_len) calls follow the same size-query convention as the client header:
 * out == NULL reports the required size.
 */
#ifndef GERYON_GROUP_SERVER_H
#define GERYON_GROUP_SERVER_H

#include <stddef.h>
#include <stdint.h>

/* Self-contained visibility macro and error codes: identical values to
 * geryon.h, guarded so the two headers may both be included in one TU. */
#ifndef GY_EXPORT
#if defined(__GNUC__) || defined(__clang__)
#define GY_EXPORT __attribute__((visibility("default")))
#else
#define GY_EXPORT
#endif
#endif

#ifndef GY_OK
#define GY_OK 0           /* Success. */
#define GY_ERR_ARG -1     /* NULL/short argument or a bad length. */
#define GY_ERR_CRYPTO -2  /* Underlying crypto provider failure. */
#define GY_ERR_VERIFY -3  /* Signature, tag, proof, or comparison mismatch. */
#define GY_ERR_TOOLONG -4 /* Input exceeds a protocol length bound. */
#define GY_ERR_STATE -6   /* Operation invalid in the current state. */
#define GY_ERR_EXPIRED -9 /* Credential presented off its redemption day. */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Suite ids (classical only; the two the group vertical serves). */
#ifndef GY_SUITE_C25519
#define GY_SUITE_C25519 0x01
#define GY_SUITE_C448 0x03
#endif

/* Member roles carried in the roster (opaque to the server; same values as the
 * client header, guarded so the two headers may both be included). */
#ifndef GY_GROUP_ROLE_DEFAULT
#define GY_GROUP_ROLE_DEFAULT 0
#define GY_GROUP_ROLE_ADMINISTRATOR 1
#define GY_GROUP_ROLE_COUNT 2 /* roles >= this are rejected by the wire codec */
#endif

/* ---- wire-buffer upper bounds (NULL-to-size query is always available) --- */

/* Split by tier, like the client header.  A caller serving an unknown suite
 * sizes to the 448 bound.  Build- and test-time checks keep these ahead of
 * the wire formulas. */
#define GY_GROUP_SERVER_PARAMS_MAX_255 256
#define GY_GROUP_SERVER_PARAMS_MAX_448 512
/* A group's public parameters (A, B), supplied by the deployer per group. */
#define GY_GROUP_GROUP_PUBLIC_MAX_255 96
#define GY_GROUP_GROUP_PUBLIC_MAX_448 160
#define GY_GROUP_AUTH_RESPONSE_MAX_255 1024
#define GY_GROUP_AUTH_RESPONSE_MAX_448 2048
#define GY_GROUP_BLIND_RESPONSE_MAX_255 1024
#define GY_GROUP_BLIND_RESPONSE_MAX_448 2048
/* A UID / ProfileKey ciphertext extracted from a verified presentation: two
 * group elements each. */
#define GY_GROUP_UID_CT_MAX_255 64
#define GY_GROUP_UID_CT_MAX_448 112
#define GY_GROUP_PK_CT_MAX_255 64
#define GY_GROUP_PK_CT_MAX_448 112

/* ---- handle and its own minimal sealed store ---------------------------- */

typedef struct gy_group_server gy_group_server;

/*
 * The server key store: a single sealed blob (ServerSecretParams).  This is
 * NOT the messaging gy_store_callbacks; the server persists exactly one record
 * and needs nothing more.  load writes the sealed blob into out (cap bytes,
 * *out_len written) and returns GY_OK with *out_len == 0 when no key has been
 * stored yet.  ctx is passed back unchanged.
 */
typedef struct gy_group_server_store {
    void *ctx;
    int (*load)(void *ctx, uint8_t *out, size_t cap, size_t *out_len);
    int (*store)(void *ctx, const uint8_t *blob, size_t blob_len);
} gy_group_server_store;

/* The largest sealed server-key blob a store must buffer for load. */
#define GY_GROUP_SERVER_KEY_BLOB_MAX 4096

/* ---- lifecycle ---------------------------------------------------------- */

/*
 * Create a fresh server: generate ServerSecretParams for suite_id, seal them
 * under (cred, cred_len) at the library's fixed Argon2id floor, and persist
 * through store.  suite_id is pinned here.  On success *out owns a heap
 * allocation freed by gy_group_server_close.  Returns GY_OK, GY_ERR_ARG on a
 * bad argument or unknown suite, GY_ERR_CRYPTO on RNG/allocation failure.
 */
GY_EXPORT int gy_group_server_create(gy_group_server **out, uint8_t suite_id,
                                     const gy_group_server_store *store,
                                     const uint8_t *cred, size_t cred_len);

/*
 * Open an existing server: recover ServerSecretParams from the sealed store
 * and (cred, cred_len).  A wrong credential and a corrupt or tampered store
 * both fail with the single uniform GY_ERR_VERIFY (no oracle).  Returns
 * GY_ERR_STATE if no server key was ever stored.  Returns GY_OK or a negative
 * GY_ERR_*.
 */
GY_EXPORT int gy_group_server_open(gy_group_server **out,
                                   const gy_group_server_store *store,
                                   const uint8_t *cred, size_t cred_len);

/* Zeroize the key and free *s (safe on NULL). */
GY_EXPORT void gy_group_server_close(gy_group_server *s);

/*
 * Export the ServerPublicParams for clients to fetch and install
 * (gy_custodian_group_install_server_params).  Size query per the buffer
 * convention.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_group_server_export_public(gy_group_server *s, uint8_t *out,
                                            size_t *out_len);

/* ---- section 8.1 operations (stateless; pure over inputs + the key) ------ */

/*
 * 7.1 GetAuthCredential (server half): issue an AuthCredential over (uid,
 * redemption_date) and prove issuance, returning the response the client
 * finishes with gy_custodian_group_receive_auth_credential.  redemption_date
 * must be a multiple of 86400; a non-day-aligned value is GY_ERR_ARG (rejected,
 * never rounded).  Size query per the buffer convention.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
GY_EXPORT int gy_group_server_issue_auth(gy_group_server *s,
                                         const uint8_t uid[16],
                                         uint64_t redemption_date, uint8_t *out,
                                         size_t *out_len);

/*
 * 7.3 GetProfileKeyCredential (server half): blind-issue a ProfileKeyCredential
 * for the authenticated member uid over the member's stored ProfileKeyCommitment
 * (commit, commit_len) and blind request (request, request_len), returning the
 * blind response the client finishes with gy_custodian_group_pk_credential_finish.
 * A malformed object or a failed request proof is GY_ERR_VERIFY.  Size query per
 * the buffer convention.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_group_server_blind_issue_pk(gy_group_server *s, const uint8_t uid[16],
                               const uint8_t *commit, size_t commit_len,
                               const uint8_t *request, size_t request_len,
                               uint8_t *out, size_t *out_len);

/*
 * Verify an AuthCredentialPresentation (pres, pres_len) under the server key,
 * bound to the group whose public parameters are (group_pub, group_pub_len, as
 * produced by gy_custodian_group_export_group_public_params).  The group public
 * key is deployer state the server holds per group; the server keeps no group
 * secret.  On success the caller receives the presented UidCiphertext
 * (out_uid_ct, NULL to skip; size query when out_uid_ct == NULL and
 * out_uid_ct_len is set) for its own access-control lookup; the server cannot
 * decrypt the UID.  A failed presentation is the uniform GY_ERR_VERIFY.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_group_server_verify_auth(gy_group_server *s,
                                          const uint8_t *group_pub,
                                          size_t group_pub_len,
                                          const uint8_t *pres, size_t pres_len,
                                          uint8_t *out_uid_ct,
                                          size_t *out_uid_ct_len);

/*
 * Verify a ProfileKeyCredentialPresentation (pres, pres_len) under the server
 * key, bound to the group (group_pub, group_pub_len) (the add-member /
 * update-profile-key path).  On success the caller receives the presented
 * UidCiphertext and ProfileKeyCiphertext (either pointer NULL to skip; size
 * query per the buffer convention on each) to store in its own member list; the
 * server decrypts neither.  A failed presentation is the uniform GY_ERR_VERIFY.
 * Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_group_server_verify_pk(
    gy_group_server *s, const uint8_t *group_pub, size_t group_pub_len,
    const uint8_t *pres, size_t pres_len, uint8_t *out_uid_ct,
    size_t *out_uid_ct_len, uint8_t *out_pk_ct, size_t *out_pk_ct_len);

/* ---- member-list assembly (roster the server serves on FetchGroupMembers) - */

/*
 * One roster entry the server holds for a group: the opaque UidCiphertext, and
 * for a joined member the opaque ProfileKeyCiphertext (both as extracted from a
 * verified presentation, or a UidCiphertext from an invite).  For an invited,
 * not-yet-joined member pk_ct is NULL, pk_ct_len 0, and has_profile_key 0.
 * role is opaque (carried, not interpreted).
 */
struct gy_group_server_member {
    const uint8_t *uid_ct;
    size_t uid_ct_len;
    const uint8_t *pk_ct;
    size_t pk_ct_len;
    uint8_t role;
    uint8_t has_profile_key;
};

/*
 * Serialize the group's member list (members[0..n), n <= the group cap) into
 * the wire object clients decode with gy_custodian_group_fetch_members.  The
 * server holds no group secret: the ciphertexts are opaque, so this is a pure
 * framing over inputs (suite_id selects the tier).  Size query per the buffer
 * convention.  A malformed ciphertext is GY_ERR_VERIFY; too many entries is
 * GY_ERR_TOOLONG.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_group_server_member_list_encode(uint8_t suite_id,
                                   const struct gy_group_server_member *members,
                                   size_t n, uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* GERYON_GROUP_SERVER_H */
