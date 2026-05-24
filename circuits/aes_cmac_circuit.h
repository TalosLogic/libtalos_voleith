/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_circuit.h - AES-CMAC as a Boolean circuit (RFC 4493)
 *
 * Implements AES-128-CMAC and AES-256-CMAC as Boolean circuits using
 * the subkey generation and CBC-MAC construction defined in RFC 4493.
 *
 * Bit/byte ordering matches aes_circuit.h throughout:
 *   - Each byte is 8 consecutive wire IDs, bit 0 = LSB, bit 7 = MSB.
 *   - message[0..7] = byte 0, message[8..15] = byte 1, etc.
 *   - message_bits must be a multiple of 8 (byte-aligned messages only).
 *
 * AND gate cost (AES-128 key, 7,200 AND gates per AES call):
 *   Subkey generation:  1 AES call (L = AES(key, 0^128))
 *   CBC-MAC:            n AES calls, where n = max(1, ceil(message_bits/128))
 *   Total:              (n + 1) × 7,200 AND gates
 *
 * For AES-256, replace 7,200 with 9,936.
 */

#ifndef VOLEITH_AES_CMAC_CIRCUIT_H
#define VOLEITH_AES_CMAC_CIRCUIT_H

#include "circuit.h"
#include <stddef.h>

/*
 * aes_cmac_circuit - AES-CMAC as a Boolean circuit.
 *
 * Appends gates to circuit `c` that compute AES-CMAC on the given key
 * and message wires, writing 128 output wire IDs to tag[0..127].
 *
 * key:          wire IDs for the AES key (128 or 256 bits).
 * key_bits:     key length in bits; must be 128 or 256.
 * message:      wire IDs for the message, byte-ordered, LSB-first per byte.
 * message_bits: message length in bits; must be a multiple of 8.
 * tag:          receives 128 wire IDs for the 128-bit CMAC tag.
 *
 * Typical usage:
 *   - key wires:     add_witness  (proving knowledge of the key)
 *   - message wires: add_instance (public message)
 *   - tag:           add_instance bits, then assert_equal to tag[] output
 */
void aes_cmac_circuit(voleith_circuit_t *c, const wire_id *key, size_t key_bits,
                      const wire_id *message, size_t message_bits,
                      wire_id tag[128]);

#endif /* VOLEITH_AES_CMAC_CIRCUIT_H */
