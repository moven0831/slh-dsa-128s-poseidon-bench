pragma circom 2.2.3;

include "params.circom";
include "adrs.circom";
include "circomlib/circuits/multiplexer.circom";

// WotsPkFromSig — recompute the WOTS+ public key from a signature
// (FIPS 205 Algorithm 8 wots_pkFromSig). Family-agnostic: relies on
// templates `SlhF()` and `SlhTlen()` defined in the family's
// hashes.circom, which the includer must pull in BEFORE this file.
//
// FIPS 205 Algorithm 8:
//   for i = 0 to len-1:
//     ADRS.setChainAddress(i)
//     tmp[i] = chain(sig[i], msg[i], w-1-msg[i], PK.seed, ADRS)
//   ADRS_pk.setType(WOTS_PK)
//   wots_pk = T_l(PK.seed, ADRS_pk, tmp)
//
// chain(X, i, s, ...) applies F s times with hash addresses [i, i+s-1].
//
// In the circuit we forward-walk 15 F's per chain starting from sig[i]:
//   cand[0] = sig[i]
//   cand[k+1] = F(pk_seed, ADRS{chain=i, hash=msg[i]+k}, cand[k]) for k=0..14
//   chain_pk[i] = cand[15 - msg[i]]
// then mux on (15 - msg[i]) ∈ [0, 15] to pick the correct candidate.
// F outputs at "wasted" positions (k > 14-msg[i]) use hash addresses
// 15..29 — these go past the FIPS 205 valid range but are unused.
//
// Cost: 35 chains × 15 F = 525 F + 35 16-way muxes + 1 Tlen.
// Worst-case across d=7 HT layers: 3675 F + 245 muxes + 7 Tlen.
//
// Soundness: prover provides cand[0..15] as a forward F-chain from
// sig[i] (no preimage required). Mux + chain pubkey constraint forces
// cand[15-msg[i]] = chain pubkey for chain i. Each F-step's ADRS hash
// address is msg[i]+k as required by FIPS 205.
template WotsPkFromSig() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input keypair;
    signal input msg_chunks[35];   // each in [0, 15]; caller range-checks
    signal input sig[35][16];
    signal output wots_pk[16];

    component f_step[35][15];
    signal cand[35][16][16];
    component chain_mux[35];
    signal chain_pk[35][16];

    for (var i = 0; i < 35; i++) {
        // Seed the chain at sig[i].
        for (var b = 0; b < 16; b++) {
            cand[i][0][b] <== sig[i][b];
        }

        // Forward chain: 15 F calls with hash addresses msg[i]+k.
        for (var k = 0; k < 15; k++) {
            f_step[i][k] = SlhF();
            for (var b = 0; b < 16; b++) {
                f_step[i][k].pk_seed[b] <== pk_seed[b];
            }
            f_step[i][k].layer     <== layer;
            f_step[i][k].tree_high <== tree_high;
            f_step[i][k].tree_low  <== tree_low;
            f_step[i][k].type_     <== 0;                      // WOTS_HASH
            f_step[i][k].keypair   <== keypair;
            f_step[i][k].chain     <== i;
            f_step[i][k].hash      <== msg_chunks[i] + k;      // witness-dependent
            for (var b = 0; b < 16; b++) {
                f_step[i][k].m[b] <== cand[i][k][b];
            }
            for (var b = 0; b < 16; b++) {
                cand[i][k + 1][b] <== f_step[i][k].out[b];
            }
        }

        // Pick the correct candidate: chain_pk[i] = cand[15 - msg[i]]
        chain_mux[i] = Multiplexer(16, 16);
        for (var k = 0; k < 16; k++) {
            for (var b = 0; b < 16; b++) {
                chain_mux[i].inp[k][b] <== cand[i][k][b];
            }
        }
        chain_mux[i].sel <== 15 - msg_chunks[i];
        for (var b = 0; b < 16; b++) {
            chain_pk[i][b] <== chain_mux[i].out[b];
        }
    }

    // Compress 35 chain pubkeys into the WOTS pubkey via Tlen.
    component tlen = SlhTlen();
    for (var b = 0; b < 16; b++) {
        tlen.pk_seed[b] <== pk_seed[b];
    }
    tlen.layer     <== layer;
    tlen.tree_high <== tree_high;
    tlen.tree_low  <== tree_low;
    tlen.type_     <== 1;       // WOTS_PK
    tlen.keypair   <== keypair;
    tlen.chain     <== 0;
    tlen.hash      <== 0;
    for (var i = 0; i < 35; i++) {
        for (var b = 0; b < 16; b++) {
            tlen.m[i * 16 + b] <== chain_pk[i][b];
        }
    }
    for (var b = 0; b < 16; b++) {
        wots_pk[b] <== tlen.out[b];
    }
}
