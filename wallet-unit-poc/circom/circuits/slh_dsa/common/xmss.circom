pragma circom 2.2.3;

include "params.circom";
include "adrs.circom";
include "wots.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/bitify.circom";

// XmssPkFromSig — recompute the XMSS root from a single XMSS signature
// (FIPS 205 Algorithm 11 xmss_pkFromSig).
//
// FIPS 205:
//   adrs.set_type_and_clear(WOTS_HASH); adrs.set_key_pair_address(idx)
//   leaf = wots_pkFromSig(sigwots, M, pk_seed, adrs)
//   adrs.set_type_and_clear(TREE); adrs.set_tree_index(idx)
//   for k = 0 to h'-1:
//     adrs.set_tree_height(k+1)
//     bit = (idx >> k) & 1
//     if bit == 0:
//         tmp = adrs.get_tree_index() / 2
//         adrs.set_tree_index(tmp)
//         node = H(pk_seed, adrs, node || auth[k])
//     else:
//         tmp = (adrs.get_tree_index() - 1) / 2
//         adrs.set_tree_index(tmp)
//         node = H(pk_seed, adrs, auth[k] || node)
//   return node
//
// For h'=9, idx ∈ [0, 511] (9 bits).
//
// Inputs:
//   pk_seed[16]
//   layer, tree_high, tree_low — XMSS sits at the given HT layer
//   idx_leaf      — the bottom-leaf index within this XMSS tree, ∈ [0, 511]
//   wots_msg[35]  — WOTS msg digest chunks (4-bit each)
//   wots_sig[35][16] — WOTS signature
//   xmss_auth[9][16] — XMSS auth path (9 nodes)
//
// Output:
//   xmss_root[16]
template XmssPkFromSig() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input idx_leaf;
    signal input wots_msg[35];
    signal input wots_sig[35][16];
    signal input xmss_auth[9][16];
    signal output xmss_root[16];

    // Decompose idx_leaf into 9 bits (LE).
    component idx_bits = Num2Bits(9);
    idx_bits.in <== idx_leaf;

    // WOTS pubkey at the leaf.
    component wots = WotsPkFromSig();
    for (var b = 0; b < 16; b++) wots.pk_seed[b] <== pk_seed[b];
    wots.layer     <== layer;
    wots.tree_high <== tree_high;
    wots.tree_low  <== tree_low;
    wots.keypair   <== idx_leaf;
    for (var i = 0; i < 35; i++) {
        wots.msg_chunks[i] <== wots_msg[i];
        for (var b = 0; b < 16; b++) wots.sig[i][b] <== wots_sig[i][b];
    }

    // Walk up h'=9 levels.
    signal node[10][16];
    for (var b = 0; b < 16; b++) node[0][b] <== wots.wots_pk[b];

    component path_h[9];
    component left_mux[9];
    component right_mux[9];

    for (var k = 0; k < 9; k++) {
        // tree_index at level (k+1) = idx_leaf >> (k+1).
        // Bit k of idx_leaf decides left/right.
        var tree_index_at_k1 = 0;
        for (var b = 0; b < 9 - (k + 1) + 1; b++) {
            // bits k+1 .. 8 of idx_leaf become bits 0 .. (8-k-1) of tree_index
            if (k + 1 + b <= 8) {
                tree_index_at_k1 += idx_bits.out[k + 1 + b] * (1 << b);
            }
        }

        // left/right selection based on bit k
        left_mux[k] = Multiplexer(16, 2);
        right_mux[k] = Multiplexer(16, 2);
        for (var b = 0; b < 16; b++) {
            // bit=0: node on left, auth on right
            left_mux[k].inp[0][b]  <== node[k][b];
            left_mux[k].inp[1][b]  <== xmss_auth[k][b];
            right_mux[k].inp[0][b] <== xmss_auth[k][b];
            right_mux[k].inp[1][b] <== node[k][b];
        }
        left_mux[k].sel  <== idx_bits.out[k];
        right_mux[k].sel <== idx_bits.out[k];

        path_h[k] = SlhH();
        for (var b = 0; b < 16; b++) path_h[k].pk_seed[b] <== pk_seed[b];
        path_h[k].layer     <== layer;
        path_h[k].tree_high <== tree_high;
        path_h[k].tree_low  <== tree_low;
        path_h[k].type_     <== 2;                       // TREE
        path_h[k].keypair   <== 0;                       // cleared by set_type
        path_h[k].chain     <== k + 1;                   // tree_height
        path_h[k].hash      <== tree_index_at_k1;        // tree_index at this level
        for (var b = 0; b < 16; b++) {
            path_h[k].m[b]      <== left_mux[k].out[b];
            path_h[k].m[16 + b] <== right_mux[k].out[b];
        }
        for (var b = 0; b < 16; b++) node[k + 1][b] <== path_h[k].out[b];
    }

    for (var b = 0; b < 16; b++) xmss_root[b] <== node[9][b];
}
