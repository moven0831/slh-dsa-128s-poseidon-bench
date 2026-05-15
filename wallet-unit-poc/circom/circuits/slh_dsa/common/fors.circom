pragma circom 2.2.3;

include "params.circom";
include "adrs.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/bitify.circom";

// ForsPkFromSig — recompute the FORS public key from a FORS signature
// (FIPS 205 Algorithm 17 fors_pkFromSig).
//
// FIPS 205 §6:
//   For each FORS tree i ∈ [0, k-1]:
//     - Get tree i's leaf index `idx_i = md_indices[i]` from the
//       message digest (a-bit chunks; for 128s, k=14 indices of a=12 bits each).
//     - The signature segment for tree i contains:
//         leaf_sk[i]      (n=16 bytes)              the FORS leaf value
//         auth_path[i][a] (a=12 nodes × n=16 bytes) auth path from leaf to root
//     - Compute the leaf hash: leaf = F(pk_seed, ADRS{type=FORS_TREE, tree_height=0, tree_index=idx_i, keypair=kp}, leaf_sk[i])
//     - Walk up a=12 levels combining with auth path (data-dependent left/right).
//     - tree_root[i] = root after all 12 levels.
//   FORS pubkey = T_k(pk_seed, ADRS{type=FORS_ROOTS, keypair=kp}, tree_root[0..13])
//
// Inputs:
//   pk_seed[16]
//   layer, tree_high, tree_low — FORS lives at the bottom HT layer (layer=0)
//   keypair                    — the FORS keypair address (= idx_leaf in the bottom XMSS tree)
//   md_indices[14]             — 12-bit FORS indices from the message digest
//   sig_fors[14][13][16]       — FORS signature: per tree, 1 leaf SK + 12 auth path nodes
//
// Output:
//   fors_pk[16]                — the FORS pubkey
template ForsPkFromSig() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input keypair;
    signal input md_indices[14];
    signal input sig_fors[14][13][16];   // [tree][0=leaf_sk, 1..12=auth_path][byte]
    signal output fors_pk[16];

    // Decompose each md_indices[i] into 12 bits for left/right path bits.
    component idx_bits[14];
    for (var i = 0; i < 14; i++) {
        idx_bits[i] = Num2Bits(12);
        idx_bits[i].in <== md_indices[i];
    }

    // For each FORS tree i, compute the tree root by hashing leaf + walking auth path.
    component leaf_f[14];
    component path_h[14][12];
    component left_mux[14][12];
    component right_mux[14][12];
    signal node[14][13][16];   // node[i][level][byte], level 0 = leaf
    signal tree_root[14][16];

    for (var i = 0; i < 14; i++) {
        // Leaf hash: F(pk_seed, ADRS{type=FORS_TREE, tree_height=0, tree_index=i*4096+md_indices[i], keypair}, leaf_sk)
        // ADRS field mapping for FORS_TREE: chain slot = tree_height (f6), hash slot = tree_index (f7).
        leaf_f[i] = SlhF();
        for (var b = 0; b < 16; b++) leaf_f[i].pk_seed[b] <== pk_seed[b];
        leaf_f[i].layer     <== layer;
        leaf_f[i].tree_high <== tree_high;
        leaf_f[i].tree_low  <== tree_low;
        leaf_f[i].type_     <== 3;       // FORS_TREE
        leaf_f[i].keypair   <== keypair;
        leaf_f[i].chain     <== 0;                                  // tree_height = 0 for leaves
        leaf_f[i].hash      <== i * 4096 + md_indices[i];           // tree_index (global)
        for (var b = 0; b < 16; b++) leaf_f[i].m[b] <== sig_fors[i][0][b];
        for (var b = 0; b < 16; b++) node[i][0][b] <== leaf_f[i].out[b];

        // Walk up 12 levels.
        // At level z (1..12), we have:
        //   left  = (idx_bits[z-1] == 0) ? node[z-1] : auth_path[z-1]
        //   right = (idx_bits[z-1] == 0) ? auth_path[z-1] : node[z-1]
        //   node[z] = H(pk_seed, ADRS{type=FORS_TREE, tree_height=z, tree_index=md_indices[i] >> z, keypair}, left || right)
        for (var z = 1; z <= 12; z++) {
            // bit (idx_bits[z-1]) determines whether node is on left or right
            // Mux: pick between node[i][z-1] (current) and sig_fors[i][z] (auth path)
            // left_mux selects node when bit=0, auth when bit=1
            // right_mux selects auth when bit=0, node when bit=1
            //
            // Implementation: bit ∈ {0, 1}.
            //   left[b]  = (1 - bit) * node[b] + bit * auth[b]
            //   right[b] = bit * node[b] + (1 - bit) * auth[b]
            // Each is 1 multiplication per byte = 16 mults per side.

            // Use fresh signals for left and right halves.
            // We'll use Multiplexer(16, 2) for clarity.
            left_mux[i][z-1] = Multiplexer(16, 2);
            right_mux[i][z-1] = Multiplexer(16, 2);
            for (var b = 0; b < 16; b++) {
                // inp[0] = node (when bit=0); inp[1] = auth (when bit=1)
                left_mux[i][z-1].inp[0][b] <== node[i][z-1][b];
                left_mux[i][z-1].inp[1][b] <== sig_fors[i][z][b];
                right_mux[i][z-1].inp[0][b] <== sig_fors[i][z][b];
                right_mux[i][z-1].inp[1][b] <== node[i][z-1][b];
            }
            left_mux[i][z-1].sel  <== idx_bits[i].out[z-1];
            right_mux[i][z-1].sel <== idx_bits[i].out[z-1];

            // node[z] at level z has ADRS{type=FORS_TREE, tree_height=z, tree_index=(i*4096+md_indices[i]) >> z}.
            // tree_index shifted: integer division of (i*4096 + md_indices[i]) by 2^z.
            // For z bits shifted: drop bottom z bits; result fits in (12-z) + log2(14) bits.
            //
            // Bit-by-bit: idx_bits[i].out gives the LE bits of md_indices[i] (a=12 bits).
            // For (i*4096 + md_indices[i]) >> z = i*2^(12-z) + (md_indices[i] >> z).
            var tree_index_shifted = i * (1 << (12 - z));
            for (var k = 0; k < 12 - z; k++) {
                tree_index_shifted += idx_bits[i].out[z + k] * (1 << k);
            }

            path_h[i][z-1] = SlhH();
            for (var b = 0; b < 16; b++) path_h[i][z-1].pk_seed[b] <== pk_seed[b];
            path_h[i][z-1].layer     <== layer;
            path_h[i][z-1].tree_high <== tree_high;
            path_h[i][z-1].tree_low  <== tree_low;
            path_h[i][z-1].type_     <== 3;                       // FORS_TREE
            path_h[i][z-1].keypair   <== keypair;
            path_h[i][z-1].chain     <== z;                       // tree_height
            path_h[i][z-1].hash      <== tree_index_shifted;      // tree_index
            for (var b = 0; b < 16; b++) {
                path_h[i][z-1].m[b]      <== left_mux[i][z-1].out[b];
                path_h[i][z-1].m[16 + b] <== right_mux[i][z-1].out[b];
            }
            for (var b = 0; b < 16; b++) node[i][z][b] <== path_h[i][z-1].out[b];
        }

        for (var b = 0; b < 16; b++) tree_root[i][b] <== node[i][12][b];
    }

    // FORS pubkey = T_k(pk_seed, ADRS{type=FORS_ROOTS, keypair}, concat(tree_root))
    component tk = SlhTk();
    for (var b = 0; b < 16; b++) tk.pk_seed[b] <== pk_seed[b];
    tk.layer     <== layer;
    tk.tree_high <== tree_high;
    tk.tree_low  <== tree_low;
    tk.type_     <== 4;           // FORS_ROOTS
    tk.keypair   <== keypair;
    tk.chain     <== 0;
    tk.hash      <== 0;
    for (var i = 0; i < 14; i++) {
        for (var b = 0; b < 16; b++) {
            tk.m[i * 16 + b] <== tree_root[i][b];
        }
    }
    for (var b = 0; b < 16; b++) fors_pk[b] <== tk.out[b];
}
