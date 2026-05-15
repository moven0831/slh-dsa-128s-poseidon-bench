pragma circom 2.2.3;

include "params.circom";
include "xmss.circom";
include "digest.circom";   // Base2bWithCsum
include "circomlib/circuits/bitify.circom";

// HtVerify — recompute the hypertree root and compare against PK.root
// (FIPS 205 Algorithm 13 ht_verify).
//
// FIPS 205 §9:
//   ADRS = empty
//   ADRS.setTreeAddress(idx_tree)
//   sig_tmp = SIG_HT.getXMSSSig(0)
//   node = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, ADRS)
//   for j = 1 to d-1:
//     idx_leaf' = idx_tree mod 2^h'
//     idx_tree' = idx_tree >> h'
//     ADRS.setLayerAddress(j); ADRS.setTreeAddress(idx_tree')
//     sig_tmp = SIG_HT.getXMSSSig(j)
//     node = xmss_pkFromSig(idx_leaf', sig_tmp, node, pk_seed, ADRS)
//   if node == pk_root: return true
//
// `M` for layer 0 is the FORS pubkey; for layer j>0 it is the previous
// XMSS root. The WOTS at layer j signs base_2b_with_csum(M_j).
template HtVerify() {
    signal input pk_seed[16];
    signal input pk_root[16];
    signal input idx_tree;            // 54 bits
    signal input idx_leaf;            // 9 bits
    signal input fors_root[16];
    signal input ht_sig[7][44][16];   // [layer][index][byte]; 0..34 = wots, 35..43 = auth
    signal output valid;

    component idx_tree_bits = Num2Bits(54);
    idx_tree_bits.in <== idx_tree;

    // Layer-by-layer XMSS verifications.
    component xmss[7];
    component chunks_compute[7];
    signal layer_msg[7][16];

    // Layer 0 message = fors_root.
    for (var b = 0; b < 16; b++) layer_msg[0][b] <== fors_root[b];

    // For layer j>0, layer_msg[j] = prev XMSS root.
    // We assign it from xmss[j-1].xmss_root after that XMSS instance.

    for (var j = 0; j < 7; j++) {
        // Compute WOTS msg chunks for this layer from layer_msg[j].
        chunks_compute[j] = Base2bWithCsum();
        for (var b = 0; b < 16; b++) chunks_compute[j].digest[b] <== layer_msg[j][b];

        xmss[j] = XmssPkFromSig();
        for (var b = 0; b < 16; b++) xmss[j].pk_seed[b] <== pk_seed[b];
        xmss[j].layer     <== j;
        xmss[j].tree_high <== 0;

        if (j == 0) {
            xmss[j].tree_low  <== idx_tree;
            xmss[j].idx_leaf  <== idx_leaf;
        } else {
            // tree_low = idx_tree >> (9*j); idx_leaf = bits [9*(j-1), 9*j-1] of orig idx_tree.
            var tl = 0;
            for (var b = 0; b < 54 - 9 * j; b++) {
                tl += idx_tree_bits.out[9 * j + b] * (1 << b);
            }
            xmss[j].tree_low <== tl;

            var il = 0;
            for (var b = 0; b < 9; b++) {
                il += idx_tree_bits.out[9 * (j - 1) + b] * (1 << b);
            }
            xmss[j].idx_leaf <== il;
        }

        for (var i = 0; i < 35; i++) {
            xmss[j].wots_msg[i] <== chunks_compute[j].chunks[i];
            for (var b = 0; b < 16; b++) xmss[j].wots_sig[i][b] <== ht_sig[j][i][b];
        }
        for (var i = 0; i < 9; i++) {
            for (var b = 0; b < 16; b++) {
                xmss[j].xmss_auth[i][b] <== ht_sig[j][35 + i][b];
            }
        }
        // Wire layer_msg[j+1] = xmss[j].xmss_root for next iteration (if any).
        if (j < 6) {
            for (var b = 0; b < 16; b++) layer_msg[j + 1][b] <== xmss[j].xmss_root[b];
        }
    }

    // Final root: xmss[6].xmss_root must equal pk_root.
    signal acc[17];
    acc[0] <== 1;
    for (var b = 0; b < 16; b++) {
        xmss[6].xmss_root[b] === pk_root[b];
        acc[b + 1] <== acc[b];
    }
    valid <== acc[16];
}
