pragma circom 2.2.3;

include "params.circom";
include "circomlib/circuits/bitify.circom";   // Num2Bits

// ADRS as 7 native field-element sub-fields (FIPS 205 §4.2).
// Common templates pass this struct into family-specific F/H/Tk/Tlen,
// each of which encodes it via a family-specific encoder (22 B for
// SHA-2, 32 B for SHAKE, 7 fe for Poseidon).
//
// Field ranges (for SLH-DSA-128s):
//   layer:     0..d-1 = 0..6         (3 bits suffice; reserved 32 bits in full ADRS)
//   tree_high: 0 always (h - h' = 54 bits fits in tree_low)
//   tree_low:  0..2^54-1
//   type_:     0..6 (one of WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF)
//   keypair:   0..2^h'-1 = 0..511 (within an XMSS layer)
//   chain:     0..len-1 = 0..34 (WOTS_HASH) or 0..k-1 = 0..13 (FORS_TREE)
//   hash:      0..a = 0..12 (FORS auth path) or 0..h'-1 = 0..8 (XMSS)
//              or 0..w-1 = 0..15 (WOTS chain)
//
// The constraint `tree_high === 0` is asserted globally below to
// prevent witness wiggle room — for 128s the high half of the tree
// address is always zero.

template AssertU32() {
    signal input v;
    component n2b = Num2Bits(32);
    n2b.in <== v;
}

template AssertU8() {
    signal input v;
    component n2b = Num2Bits(8);
    n2b.in <== v;
}

template AssertU54() {
    signal input v;
    component n2b = Num2Bits(54);
    n2b.in <== v;
}

// Range-check the 7 sub-fields and enforce tree_high === 0.
// Use this once per ADRS bundle (typically inside the common templates
// where an ADRS is materialized).
template AdrsRangeCheck() {
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;

    // For 128s, tree_high must be zero (h - h' = 54 fits in tree_low).
    tree_high === 0;

    // Range-check each subfield:
    component cl = AssertU8();   cl.v <== layer;
    component cth = AssertU32(); cth.v <== tree_high;
    component ctl = AssertU54(); ctl.v <== tree_low;
    component ct = AssertU8();   ct.v <== type_;
    component ck = AssertU32();  ck.v <== keypair;
    component cc = AssertU32();  cc.v <== chain;
    component ch = AssertU32();  ch.v <== hash;
}

// Helper: build the 7-tuple from layer + tree (split) + type explicitly.
// (Just exposes the same signals; pure wire-renaming, zero R1CS cost
// other than the AdrsRangeCheck if you wire it in.)
//
// Family-specific encoders consume these 7 signals directly.
