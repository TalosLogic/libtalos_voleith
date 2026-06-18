# Shipshape example corpus

Hand-written `.ship` example files (W7.1 of
`docs/SHIPSHAPE_IMPLEMENTATION_PLAN.md`), shipped as the structural
compositions the empty v1 bundled stdlib set pushes into user space (ISA
design §4). `tests/test_shipshape_examples.c` parses every file here; the
end-to-end parse / witness / prove / verify of one of them is the W7.2
example program.

| File | Demonstrates |
|------|--------------|
| `aes128_key_knowledge.ship` | AES-128 key-knowledge proof: a Tier 2a `stdlib/crypto/aes/encrypt_128` call, with the result checked against a public ciphertext instance. |
| `cmac_tag_verify.ship` | AES-CMAC key knowledge over a public message: a PARAMETRIC registry call (`stdlib/crypto/cmac/aes_128`, `n` inferred from the message vector). |
| `merkle_path_public.ship` | Depth-2 Merkle path with statically-resolved public directions; the node compression `H(L,R) = AES_L(R)` is a `user/compress` subcircuit. |
| `merkle_path_secret.ship` | Depth-2 Merkle path with secret directions: each level's direction is a witness `bit`, and a per-byte `MUX` selects the `(left, right)` order so the path shape leaks nothing (ring-signature style). |

All four use the keyed compression `H(L,R) = AES_L(R)` for brevity; a
production Merkle tree would use a Davies-Meyer feed-forward
(`AES_L(R) XOR R`) or one of the `stdlib/crypto/grostl/*` wide-node
hashes. The compression is written as a `user/*` subcircuit because the
v1 `stdlib/structural/*` namespace is empty (ISA §4).
