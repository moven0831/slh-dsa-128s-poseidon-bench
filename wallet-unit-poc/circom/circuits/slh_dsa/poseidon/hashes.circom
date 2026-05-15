pragma circom 2.2.3;

include "poseidon_wrap.circom";

// Non-standard Poseidon-based SLH-DSA primitives over secq256r1.
//
// **NON-STANDARD; FOR BENCHMARKING ONLY.**
// See `circuits/poseidon/README.md` and main README for caveats.
//
// Encoding choices:
//   - ADRS = 7 native field elements (one per sub-field).
//   - pk_seed (16 B) packs into 1 field element (LE).
//   - n-byte slots (16 B) pack into 1 field element each.
//   - Domain-separation tag prepended to every Poseidon call:
//       F = 0, H = 1, T_k = 2, T_len = 3, H_msg = 4
//   - Truncation: low 128 bits of one Poseidon output for n-byte slots.
//     For H_msg (m=30 bytes), use PoseidonHash30 (two Poseidon calls).
//
// Arities (number of Poseidon inputs after tag prefix):
//   F:    1 (tag) + 1 (pk_seed) + 7 (adrs) + 1  (m)    = 10  ≤ 16 ✓
//   H:    1 (tag) + 1 (pk_seed) + 7 (adrs) + 2  (m1m2) = 11  ≤ 16 ✓
//   T_k:  1 (tag) + 1 (pk_seed) + 7 (adrs) + 14 (roots)= 23  > 16; use Merkle reduce
//   T_len:1 (tag) + 1 (pk_seed) + 7 (adrs) + 35 (ends) = 44  > 16; use Merkle reduce
//   H_msg:1 (tag) + 1 (R) + 1 (pk_seed) + 1 (pk_root) + 64 (msg) = 68; Merkle reduce

template SlhF() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[16];
    signal output out[16];

    component pack_pk = PackBytes16ToFe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component pack_m = PackBytes16ToFe();
    for (var b = 0; b < 16; b++) pack_m.bytes[b] <== m[b];

    component p = PoseidonHash16(10);
    p.inputs[0] <== 0;            // tag F
    p.inputs[1] <== pack_pk.fe;
    p.inputs[2] <== layer;
    p.inputs[3] <== tree_high;
    p.inputs[4] <== tree_low;
    p.inputs[5] <== type_;
    p.inputs[6] <== keypair;
    p.inputs[7] <== chain;
    p.inputs[8] <== hash;
    p.inputs[9] <== pack_m.fe;
    for (var k = 0; k < 16; k++) out[k] <== p.out[k];
}

template SlhH() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[32];   // m1 || m2
    signal output out[16];

    component pack_pk = PackBytes16ToFe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component pack_m1 = PackBytes16ToFe();
    component pack_m2 = PackBytes16ToFe();
    for (var b = 0; b < 16; b++) pack_m1.bytes[b] <== m[b];
    for (var b = 0; b < 16; b++) pack_m2.bytes[b] <== m[16 + b];

    component p = PoseidonHash16(11);
    p.inputs[0] <== 1;
    p.inputs[1] <== pack_pk.fe;
    p.inputs[2] <== layer;
    p.inputs[3] <== tree_high;
    p.inputs[4] <== tree_low;
    p.inputs[5] <== type_;
    p.inputs[6] <== keypair;
    p.inputs[7] <== chain;
    p.inputs[8] <== hash;
    p.inputs[9] <== pack_m1.fe;
    p.inputs[10] <== pack_m2.fe;
    for (var k = 0; k < 16; k++) out[k] <== p.out[k];
}

template SlhTk() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[224];   // 14 roots × 16 bytes
    signal output out[16];

    component pack_pk = PackBytes16ToFe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component pack_roots[14];
    for (var i = 0; i < 14; i++) {
        pack_roots[i] = PackBytes16ToFe();
        for (var b = 0; b < 16; b++) pack_roots[i].bytes[b] <== m[i * 16 + b];
    }

    // Reduce 14 root field elements to 1 via Merkle.
    component reduce = PoseidonReduce(14);
    for (var i = 0; i < 14; i++) reduce.inputs[i] <== pack_roots[i].fe;

    component p = PoseidonHash16(10);
    p.inputs[0] <== 2;            // tag T_k
    p.inputs[1] <== pack_pk.fe;
    p.inputs[2] <== layer;
    p.inputs[3] <== tree_high;
    p.inputs[4] <== tree_low;
    p.inputs[5] <== type_;
    p.inputs[6] <== keypair;
    p.inputs[7] <== chain;
    p.inputs[8] <== hash;
    p.inputs[9] <== reduce.out;
    for (var k = 0; k < 16; k++) out[k] <== p.out[k];
}

template SlhTlen() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[560];   // 35 endpoints × 16 bytes
    signal output out[16];

    component pack_pk = PackBytes16ToFe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component pack_ends[35];
    for (var i = 0; i < 35; i++) {
        pack_ends[i] = PackBytes16ToFe();
        for (var b = 0; b < 16; b++) pack_ends[i].bytes[b] <== m[i * 16 + b];
    }

    component reduce = PoseidonReduce(35);
    for (var i = 0; i < 35; i++) reduce.inputs[i] <== pack_ends[i].fe;

    component p = PoseidonHash16(10);
    p.inputs[0] <== 3;            // tag T_len
    p.inputs[1] <== pack_pk.fe;
    p.inputs[2] <== layer;
    p.inputs[3] <== tree_high;
    p.inputs[4] <== tree_low;
    p.inputs[5] <== type_;
    p.inputs[6] <== keypair;
    p.inputs[7] <== chain;
    p.inputs[8] <== hash;
    p.inputs[9] <== reduce.out;
    for (var k = 0; k < 16; k++) out[k] <== p.out[k];
}

template SlhHMsg() {
    signal input r[16];
    signal input pk_seed[16];
    signal input pk_root[16];
    signal input m[1024];
    signal output out[30];

    component pack_r = PackBytes16ToFe();
    component pack_pk_seed = PackBytes16ToFe();
    component pack_pk_root = PackBytes16ToFe();
    for (var b = 0; b < 16; b++) {
        pack_r.bytes[b]       <== r[b];
        pack_pk_seed.bytes[b] <== pk_seed[b];
        pack_pk_root.bytes[b] <== pk_root[b];
    }

    component pack_m[64];
    for (var i = 0; i < 64; i++) {
        pack_m[i] = PackBytes16ToFe();
        for (var b = 0; b < 16; b++) pack_m[i].bytes[b] <== m[i * 16 + b];
    }

    component reduce = PoseidonReduce(64);
    for (var i = 0; i < 64; i++) reduce.inputs[i] <== pack_m[i].fe;

    component p = PoseidonHash30(4);    // 4 inputs: R, pk_seed, pk_root, msg_digest
    p.inputs[0] <== pack_r.fe;
    p.inputs[1] <== pack_pk_seed.fe;
    p.inputs[2] <== pack_pk_root.fe;
    p.inputs[3] <== reduce.out;

    for (var k = 0; k < 30; k++) out[k] <== p.out[k];
}
