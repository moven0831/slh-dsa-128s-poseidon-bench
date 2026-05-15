pragma circom 2.2.3;

include "params.circom";
include "digest.circom";
include "fors.circom";
include "ht.circom";
include "xmss.circom";

// SlhDsaVerify — top-level SLH-DSA-128s verifier.
//
// Public inputs (concatenated as `pk[32]` and `msg[1024]`):
//   pk_seed  = pk[0..16]
//   pk_root  = pk[16..32]
//   msg      = 1024 bytes
//
// Witness:
//   sig: 7856 bytes laid out as
//     R[16] || sig_fors[14*13*16=2912] || sig_ht[7*44*16=4928]
//
// Output: valid (== 1 if SLH_DSA_Verify(PK, M, SIG) = 1; circuit
// otherwise unsatisfied).
//
// FIPS 205 Algorithm 20 slh_verify_internal:
//   R = SIG[0..n]
//   SIG_FORS = SIG[n..n+(1+a)*k*n]
//   SIG_HT   = SIG[n+(1+a)*k*n..]
//   ADRS = newADRS()
//   digest = H_msg(R, PK.seed, PK.root, M)
//   md = digest[0..21]
//   idx_tree = toInt(digest[21..28], 7) mod 2^54
//   idx_leaf = toInt(digest[28..30], 2) mod 2^9
//   ADRS.setTreeAddress(idx_tree)
//   ADRS.setType(FORS_TREE)
//   ADRS.setKeyPairAddress(idx_leaf)
//   PK_FORS = fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
//   return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
template SlhDsaVerify() {
    signal input pk[32];
    signal input msg[1024];
    signal input r[16];
    signal input sig_fors[14][13][16];
    signal input sig_ht[7][44][16];
    signal output valid;

    signal pk_seed[16];
    signal pk_root[16];
    for (var i = 0; i < 16; i++) {
        pk_seed[i] <== pk[i];
        pk_root[i] <== pk[16 + i];
    }

    // Step 1: compute H_msg digest.
    component hmsg = SlhHMsg();
    for (var i = 0; i < 16; i++)   hmsg.r[i] <== r[i];
    for (var i = 0; i < 16; i++)   hmsg.pk_seed[i] <== pk_seed[i];
    for (var i = 0; i < 16; i++)   hmsg.pk_root[i] <== pk_root[i];
    for (var i = 0; i < 1024; i++) hmsg.m[i] <== msg[i];

    // Step 2: parse digest into md, idx_tree, idx_leaf.
    component parse = ParseDigest();
    for (var i = 0; i < 30; i++) parse.digest[i] <== hmsg.out[i];

    // Step 3: FORS pubkey from signature.
    component fors = ForsPkFromSig();
    for (var b = 0; b < 16; b++) fors.pk_seed[b] <== pk_seed[b];
    fors.layer     <== 0;             // FORS lives at HT layer 0
    fors.tree_high <== 0;
    fors.tree_low  <== parse.idx_tree;
    fors.keypair   <== parse.idx_leaf;
    for (var i = 0; i < 14; i++) fors.md_indices[i] <== parse.md_indices[i];
    for (var i = 0; i < 14; i++) {
        for (var j = 0; j < 13; j++) {
            for (var b = 0; b < 16; b++) fors.sig_fors[i][j][b] <== sig_fors[i][j][b];
        }
    }

    // Step 4: HT verification (HtVerify computes WOTS msg chunks
    // internally from layer_msg, which is fors_root for layer 0 and the
    // previous XMSS root for layers 1..6).
    component ht = HtVerify();
    for (var b = 0; b < 16; b++) ht.pk_seed[b] <== pk_seed[b];
    for (var b = 0; b < 16; b++) ht.pk_root[b] <== pk_root[b];
    ht.idx_tree <== parse.idx_tree;
    ht.idx_leaf <== parse.idx_leaf;
    for (var b = 0; b < 16; b++) ht.fors_root[b] <== fors.fors_pk[b];
    for (var j = 0; j < 7; j++) {
        for (var i = 0; i < 44; i++) {
            for (var b = 0; b < 16; b++) ht.ht_sig[j][i][b] <== sig_ht[j][i][b];
        }
    }

    valid <== ht.valid;
}
