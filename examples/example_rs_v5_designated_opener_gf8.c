/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_v5_designated_opener_gf8.c - V5 designated-opener ring signature.
 *
 * Statement: "I am one of N enrolled members, and I attach a tracing tag that
 * ONLY the designated opener (holder of the QC-MDPC opener secret key) can turn
 * back into my enrolled identity."  The signature is anonymous to everyone else;
 * the opener can de-anonymize it, and nobody else can.
 *
 * Split-custody narrative (why this is useful):
 *   - The OPENER holds the QC-MDPC secret key.  Given a signature it recovers an
 *     opaque identity handle `id` (a random per-member token), nothing more.
 *   - A separate ENROLLMENT AUTHORITY holds the id -> real-member mapping.
 *     Neither party alone can both trace a signature AND name the human: opening
 *     needs the opener key, naming needs the authority's table.
 * This example plays every role, so the "revealed" support/id come straight from
 * the signing side and no decoder is needed: it de-anonymizes with
 * voleith_rs_opener_verify (the software opener that re-checks s = M*e^T and the
 * DEM), which is exactly what the real opener's decode-then-recover collapses to
 * once the error e is known.  The end-to-end path through the real
 * libtalos_syndrome decoder is exercised by tests/test_rs_opener_oracle_gf8.c.
 *
 * Demonstration:
 *   1. Enroll an 8-member depth-3 ring; each leaf carries a member id.
 *   2. Seal member #6's id into a fresh tracing tag (support, s, tag_ct).
 *   3. Sign as member #6; verify.
 *   4. Serialize to the VRSC v2 envelope (proof + opener section) and read the
 *      opener tag back; show the v1 opt-down (proof only, opener dropped).
 *   5. "Open": recover authorship from the tag with voleith_rs_opener_verify,
 *      and show a mismatched id is rejected.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "node_hash_vt.h"
#include "rs_gf8.h"
#include "rs_gf8_circuit.h"
#include "rs_opener_argus_gf8.h"
#include "rs_opener_gf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double
elapsed_ms(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec) * 1000.0 +
           (double)(end.tv_nsec - start.tv_nsec) / 1.0e6;
}

/*
 * Build the superset circuit for `cfg` (no witness/proof) and print its slot
 * profile: the QuickSilver opening degree, the witness / instance / gate / wire
 * counts, and the constraint mix.  Called with the opener ON and OFF so the
 * marginal cost of the designated-opener branch is visible.  In GF(2^8) one wire
 * = one byte, and each inversion S-box contributes exactly one inv_in witness
 * byte and two assert_product constraints.
 */
static void
print_circuit_profile(const voleith_rs_config_t *cfg)
{
    voleith_rs_layout_t L;
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    if (c == NULL || voleith_rs_build_circuit(c, cfg, &L) != 0) {
        if (c != NULL)
            voleith_gf8_circuit_free(c);
        printf("  (circuit build failed)\n");
        return;
    }

    printf("  QS opening degree d       : %u\n",
           voleith_gf8_circuit_qs_degree(c));
    printf("  witness slots             : %zu\n",
           voleith_gf8_circuit_witness_count(c));
    printf("  instance slots            : %zu\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  total wires               : %zu\n",
           voleith_gf8_circuit_wire_count(c));
    printf("  MUL gates (VOLE slots)    : %zu\n",
           voleith_gf8_circuit_mul_count(c));
    printf("  S-box inv witnesses       : membership %zu + opener KDF %zu\n",
           L.membership.owf_invin_bytes + L.membership.path_invin_bytes,
           L.opener_kdf_invin_bytes);
    printf("  assert_product constraints: %zu\n",
           voleith_gf8_circuit_assert_product_count(c));
    printf("  less-than constraints     : %zu\n",
           voleith_gf8_circuit_lt_count(c));
    printf("  syndrome constraints      : %zu\n",
           voleith_gf8_circuit_syndrome_count(c));
    printf("  total constraints         : %zu\n",
           voleith_gf8_circuit_constraint_count(c));
    if (cfg->enable_opener)
        printf("  opener witness/instance   : support %zu B, s %zu B, "
               "tag_ct %zu B\n",
               L.opener_support_bytes, L.inst_opener_s_bytes,
               L.inst_opener_tag_ct_bytes);

    voleith_gf8_circuit_free(c);
}

int
main(void)
{
    /*
     * lambda = 128.  The opener set (128_5) fixes the QC-MDPC dimensions and the
     * DEM key width (key_bytes = 16); the tree node hash and proof set are the
     * usual 128-bit choices.  id / sk are key_bytes wide.
     */
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const voleith_rs_opener_argus_set_t oset =
        VOLEITH_RS_OPENER_ARGUS_SET_128_5;
    voleith_params_t params = voleith_params_em_128f;

    const voleith_rs_opener_argus_params_t *op =
        voleith_rs_opener_argus_params(oset);
    const voleith_rs_opener_scheme_t *scheme =
        voleith_rs_opener_scheme(VOLEITH_RS_OPENER_SCHEME_ARGUS);

    const size_t depth_m = 3;
    const size_t n_members = (size_t)1u << depth_m;
    const size_t signer = 6;
    int ok = 1;

    if (op == NULL || scheme == NULL) {
        fprintf(stderr, "opener params/scheme unavailable in this build\n");
        return 1;
    }

    const size_t kb = op->key_bytes; /* = 16 = sk / id / DEM-key width */
    const size_t W = vt->node_bytes;
    const size_t Mlen = (size_t)(op->n0 - 1u) * op->block_bytes;

    /* Public opener key M ((n0-1) circulant blocks).  In a deployment this comes
     * from the opener's syndrome keypair; here it is fixed public bytes, since
     * this example does not run the decoder (verify re-checks s = M*e^T against
     * the same M either way). */
    uint8_t *M = malloc(Mlen);
    uint8_t *sks = calloc(n_members, kb);
    uint8_t *ids = calloc(n_members, kb);
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    voleith_rs_path_t *paths = calloc(n_members, sizeof(*paths));
    uint8_t *sib = calloc(n_members, depth_m * W);
    uint32_t *support = malloc((size_t)op->t * sizeof(uint32_t));
    uint8_t *s = malloc(op->block_bytes);
    uint8_t *tag_ct = malloc(kb);
    if (M == NULL || sks == NULL || ids == NULL || paths == NULL ||
        sib == NULL || support == NULL || s == NULL || tag_ct == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < Mlen; i++)
        M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    for (size_t i = 0; i < n_members * kb; i++) {
        sks[i] = (uint8_t)(i * 31u + 0x11u);
        ids[i] = (uint8_t)(0xA0u + i); /* per-member opaque id handle */
    }

    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = kb;
    cfg.membership.depth_m = depth_m;
    cfg.enable_opener = 1;
    cfg.opener_set = oset;
    cfg.opener_pk = M;
    cfg.opener_pk_bytes = Mlen;

    const uint8_t *signer_id = ids + signer * kb;

    printf("=== V5 designated-opener ring signature ===\n");
    printf("Ring:    %zu members, depth %zu, tree hash %s\n", n_members,
           depth_m, vt->name);
    printf("Opener:  set 128_5 (p=%u, n=%u, t=%u), DEM key %zu B\n", op->p,
           op->n, op->t, kb);
    printf("Signer:  member #%zu; its id is traceable only by the opener\n\n",
           signer);

    /*
     * Circuit profile: what the designated opener costs.  The opener branch
     * adds the syndrome relation (proven at opening degree d = idx_bits, not the
     * usual 2), the ascending/range less-than chain over the support, and the
     * KDF+DEM S-boxes.  Building the same ring with the opener OFF isolates that
     * marginal cost.
     */
    printf("Circuit profile (opener ON):\n");
    print_circuit_profile(&cfg);
    {
        voleith_rs_config_t cfg_noop = cfg;

        cfg_noop.enable_opener = 0;
        cfg_noop.opener_pk = NULL;
        cfg_noop.opener_pk_bytes = 0;
        printf("Circuit profile (opener OFF, same ring):\n");
        print_circuit_profile(&cfg_noop);
    }
    printf("\n");

    /* 1. Seal member #6's id into a fresh tracing tag. */
    uint8_t rnd[MERKLE_VT_MAX_NODE_BYTES];
    for (size_t i = 0; i < kb; i++)
        rnd[i] = (uint8_t)(0x5Au + i);
    if (voleith_rs_opener_seal(&cfg, rnd, kb, signer_id, kb, support, s,
                               tag_ct) != 0) {
        fprintf(stderr, "opener_seal failed\n");
        return 1;
    }

    /* 2. Enroll the ring: each leaf = OWF(sk || id) via the opener-aware
     * streaming builder (leaf #6 carries the sealed id). */
    voleith_rs_ring_builder_t *rb = NULL;
    if (voleith_rs_ring_build_init(&rb, &cfg, n_members, root, paths, sib) !=
        0) {
        fprintf(stderr, "ring_build_init failed\n");
        return 1;
    }
    for (size_t i = 0; i < n_members; i++) {
        if (voleith_rs_ring_member_begin(rb) != 0 ||
            voleith_rs_ring_member_set(rb, VOLEITH_RS_LEAF_FIELD_SK,
                                       sks + i * kb, kb) != 0 ||
            voleith_rs_ring_member_set(rb, VOLEITH_RS_LEAF_FIELD_ID,
                                       ids + i * kb, kb) != 0 ||
            voleith_rs_ring_member_end(rb) != 0) {
            voleith_rs_ring_build_free(rb);
            fprintf(stderr, "ring enroll failed\n");
            return 1;
        }
    }
    if (voleith_rs_ring_build_final(rb) != 0) { /* consumes rb */
        fprintf(stderr, "ring_build_final failed\n");
        return 1;
    }

    /* 3. Sign as member #6, binding the tracing tag; verify. */
    const uint8_t m[] = "V5 example: anonymous now, openable by the authority";
    size_t m_len = sizeof(m) - 1;
    voleith_rs_path_t path = paths[signer];
    path.opener_support = support;
    path.commit_id = signer_id; /* Q8: opener id rides commit_id */
    voleith_rs_public_t pub;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.opener_s = s;
    pub.opener_tag_ct = tag_ct;

    voleith_rs_sig_t sig = {NULL, 0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = voleith_rs_sign(&sig, &cfg, &params, sks + signer * kb, NULL,
                             &path, &pub, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }
    int v = voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len);
    printf("Sign:    %zu proof bytes in %.2f ms\n", sig.len,
           elapsed_ms(t0, t1));
    printf("Verify:  %s\n", v == 0 ? "PASS" : "FAIL");
    ok = ok && v == 0;

    /* 4. VRSC v2 envelope: proof + opener section; read the opener tag back. */
    voleith_rs_sig_packer_t *packer = NULL;
    uint8_t *blob = NULL;
    const uint8_t *tag = NULL;
    size_t tag_len = 0;
    if (voleith_rs_sig_pack_init(&packer, &cfg, &params,
                                 VOLEITH_RS_SIG_FORMAT_AUTO) != 0 ||
        voleith_rs_sig_pack_proof(packer, &sig) != 0 ||
        voleith_rs_sig_pack_opener(packer, &pub) != 0) {
        fprintf(stderr, "v2 pack failed\n");
        return 1;
    }
    size_t blen = voleith_rs_sig_pack_len(packer);
    blob = malloc(blen);
    if (blob == NULL ||
        voleith_rs_sig_pack_final(packer, blob, blen, NULL) != 0) {
        fprintf(stderr, "v2 pack_final failed\n");
        return 1;
    }
    voleith_rs_sig_unpacker_t *unpacker = NULL;
    if (voleith_rs_sig_unpack_init(&unpacker, blob, blen, &cfg, &params) != 0 ||
        voleith_rs_sig_unpack_opener(unpacker, &tag, &tag_len) != 0) {
        fprintf(stderr, "v2 unpack opener failed\n");
        return 1;
    }
    printf("\nEnvelope: v2 %zu bytes = proof (%zu) + opener tag (%zu)\n", blen,
           sig.len, tag_len);
    printf("          tag = hash_id(1) || s(%zu) || tag_ct(%zu)\n",
           op->block_bytes, kb);

    /* v1 opt-down: proof only, opener section dropped (openability removed). */
    voleith_rs_sig_packer_t *packer1 = NULL;
    if (voleith_rs_sig_pack_init(&packer1, &cfg, &params,
                                 VOLEITH_RS_SIG_FORMAT_V1) != 0 ||
        voleith_rs_sig_pack_proof(packer1, &sig) != 0) {
        fprintf(stderr, "v1 pack failed\n");
        return 1;
    }
    size_t blen1 = voleith_rs_sig_pack_len(packer1);
    printf("          v1 opt-down %zu bytes (opener dropped: unopenable)\n",
           blen1);
    voleith_rs_sig_pack_free(packer1);
    ok = ok && blen1 < blen;

    /* 5. Open: recover authorship from the tag.  The opener (playing its role
     * with the known support) checks s = M*e^T and that the DEM decrypts to the
     * enrolled id -> traces the signature to member #6. */
    voleith_rs_opener_witness_t w;
    voleith_rs_opener_argus_witness(&w, support);
    int opened = voleith_rs_opener_verify(scheme, (uint32_t)oset, M, tag,
                                          tag_len, &w, signer_id, kb);
    printf("\nOpen:    trace tag -> member #%zu id -> %s\n", signer,
           opened == VOLEITH_RS_OPENER_OK ? "OPENED" : "failed?!");
    ok = ok && opened == VOLEITH_RS_OPENER_OK;

    /* A different member's id does not open this tag (the DEM binds THIS id). */
    uint8_t other_id[MERKLE_VT_MAX_NODE_BYTES];
    memcpy(other_id, signer_id, kb);
    other_id[0] ^= 0x01u;
    int mis = voleith_rs_opener_verify(scheme, (uint32_t)oset, M, tag, tag_len,
                                       &w, other_id, kb);
    printf("Bind:    trace tag against a wrong id -> %s\n",
           mis == VOLEITH_RS_OPENER_EIDENTITY ? "REJECT" : "accept?!");
    ok = ok && mis == VOLEITH_RS_OPENER_EIDENTITY;

    voleith_rs_sig_unpack_free(unpacker);
    voleith_rs_sig_free(&sig);
    free(blob);
    free(M);
    free(sks);
    free(ids);
    free(paths);
    free(sib);
    free(support);
    free(s);
    free(tag_ct);

    printf("\n%s\n", ok ? "OK" : "FAILED");
    return ok ? 0 : 1;
}
