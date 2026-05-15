pragma circom 2.2.3;

include "params.circom";
include "circomlib/circuits/bitify.circom";

// Parse the 30-byte H_msg output into:
//   md[14]      — k=14 FORS leaf indices, each a=12 bits (md = 21 bytes = 168 bits)
//   idx_tree    — 54-bit hypertree tree address (bytes 21..27, but only 54 bits wide)
//   idx_leaf    — 9-bit leaf-within-bottom-tree index (bytes 28..29, but only 9 bits)
//
// FIPS 205 §10.3 Algorithm 19 slh_verify_internal does:
//   digest = H_msg(R, PK.seed, PK.root, M)
//   md = digest[0..21]
//   idx_tree_bytes = digest[21..28]   (7 bytes; only low 54 bits used)
//   idx_leaf_bytes = digest[28..30]   (2 bytes; only low 9 bits used)
//   idx_tree = toInt(idx_tree_bytes, 7) mod 2^54
//   idx_leaf = toInt(idx_leaf_bytes, 2) mod 2^9
//   indices  = base_2b(md, a=12, k=14) — 14 12-bit chunks
//
// Note: idx_tree is BE-encoded across 7 bytes, then masked to 54 bits.
// The "mod 2^54" effectively zero-extends only the low 54 bits.
template ParseDigest() {
    signal input digest[30];
    signal output md_indices[14];   // each ∈ [0, 4095]
    signal output idx_tree;         // < 2^54
    signal output idx_leaf;         // < 2^9

    // Decompose digest[0..21] (md) into 168 bits (BE per byte), then
    // group into 14 chunks of 12 bits (MSB-first across the chunk).
    // base_2b with b=12 reads the bit stream in MSB-first order per byte.
    component md_bits[21];
    for (var i = 0; i < 21; i++) {
        md_bits[i] = Num2Bits(8);
        md_bits[i].in <== digest[i];
    }
    // bit_be[k] = the k-th bit in the BE bitstream (k ∈ [0, 168))
    // For byte i, bit position p (LE within byte: bit 0 is LSB), the BE position is 8*i + (7 - p).
    // So bit_be[8*i + (7-p)] = md_bits[i].out[p] for p=0..7.

    for (var c = 0; c < 14; c++) {
        // chunk c spans bits [12*c, 12*c+11] in the BE stream.
        // chunk value = sum_{j=0..11} bit_be[12*c + j] * 2^(11 - j)
        var sum = 0;
        for (var j = 0; j < 12; j++) {
            var be_pos = 12 * c + j;
            var byte_idx = be_pos \ 8;
            var bit_in_byte_be = be_pos % 8;          // 0 = MSB
            var bit_in_byte_le = 7 - bit_in_byte_be;  // 0 = LSB
            sum += md_bits[byte_idx].out[bit_in_byte_le] * (1 << (11 - j));
        }
        md_indices[c] <== sum;
    }

    // idx_tree = toInt(digest[21..28], 7) mod 2^54
    // toInt in FIPS 205 reads BE. So integer = digest[21]*2^48 + digest[22]*2^40 + ... + digest[27]*2^0.
    // Mask to 54 bits: drop the top (56 - 54) = 2 bits.
    component idx_tree_bytes[7];
    for (var i = 0; i < 7; i++) {
        idx_tree_bytes[i] = Num2Bits(8);
        idx_tree_bytes[i].in <== digest[21 + i];
    }
    // Compute toInt(digest[21..28], 7) — 56 bit value:
    //   sum over i=0..6 of digest[21+i] * 2^(8*(6-i))
    // To extract low 54 bits: drop the top 2 bits, which are bits [54, 55] of the 56-bit value.
    // Bit position k (LE in toInt result) = bit (within byte (k\8) from LSB), where byte index in toInt is (6 - k\8).
    var idx_tree_sum = 0;
    for (var k = 0; k < 54; k++) {
        var byte_pos_le = k \ 8;          // 0 = lowest byte (i.e., digest[27])
        var bit_in_byte_le = k % 8;
        var byte_idx_in_digest = 21 + (6 - byte_pos_le);
        // digest[byte_idx] bit `bit_in_byte_le` (LE) contributes to bit k of idx_tree
        // We have already decomposed digest[21+i] above, where i goes 0..6.
        // For byte_pos_le=p (0=lowest), digest index = 21 + (6-p), and the corresponding
        // idx_tree_bytes[6-p] holds its bits.
        var bytes_array_index = 6 - byte_pos_le;
        idx_tree_sum += idx_tree_bytes[bytes_array_index].out[bit_in_byte_le] * (1 << k);
    }
    idx_tree <== idx_tree_sum;

    // idx_leaf = toInt(digest[28..30], 2) mod 2^9
    component idx_leaf_bytes[2];
    for (var i = 0; i < 2; i++) {
        idx_leaf_bytes[i] = Num2Bits(8);
        idx_leaf_bytes[i].in <== digest[28 + i];
    }
    // 16-bit BE value masked to 9 bits.
    // Bit k (LE in toInt result) = bit (within byte (1 - k\8)) at position (k%8).
    var idx_leaf_sum = 0;
    for (var k = 0; k < 9; k++) {
        var byte_pos_le = k \ 8;
        var bit_in_byte_le = k % 8;
        var bytes_array_index = 1 - byte_pos_le;
        idx_leaf_sum += idx_leaf_bytes[bytes_array_index].out[bit_in_byte_le] * (1 << k);
    }
    idx_leaf <== idx_leaf_sum;
}

// Base2bWithCsum: given a 16-byte n-byte hash output, compute the 35
// 4-bit chunks that WOTS_pkFromSig consumes. This is the message
// + checksum encoding from FIPS 205 §5.3.2 / Algorithm 8 prep.
//
// Steps:
//   1. base_2b(digest, lg_w=4, len_1=32): 32 nibbles MSB-first per byte.
//   2. csum = sum_{i=0..31} (w-1 - msg[i]) = 32*15 - sum(msg[i]).
//   3. csum_shifted = csum << ((8 - (len_2 * lg_w) % 8) % 8) = csum << 4
//      (since 12 bits = 1.5 bytes, we round up to 2 bytes and shift left by 4).
//   4. csum_bytes = toByte(csum_shifted, 2)  (2 bytes BE)
//   5. csum_chunks = base_2b(csum_bytes, lg_w=4, len_2=3): 3 nibbles MSB-first.
//      Yields: msg[32]=csum>>8, msg[33]=(csum>>4)&0xF, msg[34]=csum&0xF.
//
// Output: 35 chunks, each ∈ [0, 15].
template Base2bWithCsum() {
    signal input digest[16];
    signal output chunks[35];

    // Step 1: extract 32 nibbles from 16 bytes (each byte → 2 nibbles, MSB-first).
    component byte_bits[16];
    for (var i = 0; i < 16; i++) {
        byte_bits[i] = Num2Bits(8);
        byte_bits[i].in <== digest[i];
    }
    for (var i = 0; i < 16; i++) {
        // High nibble (bits 4..7 of byte LE) → chunks[2*i]
        var hi = 0;
        for (var p = 0; p < 4; p++) hi += byte_bits[i].out[4 + p] * (1 << p);
        chunks[2 * i] <== hi;
        // Low nibble (bits 0..3 of byte LE) → chunks[2*i + 1]
        var lo = 0;
        for (var p = 0; p < 4; p++) lo += byte_bits[i].out[p] * (1 << p);
        chunks[2 * i + 1] <== lo;
    }

    // Step 2: csum = 32*15 - sum_{i=0..31} chunks[i]
    var csum_acc = 0;
    for (var i = 0; i < 32; i++) csum_acc += chunks[i];
    signal csum;
    csum <== 32 * 15 - csum_acc;

    // Step 3,4,5: extract 3 nibbles from csum.
    // csum < 32*15 = 480 < 2^9. After <<4 shift, still <= 480*16 = 7680 < 2^13.
    // 2 BE bytes of (csum<<4): byte0 = csum>>4, byte1 = (csum<<4)&0xFF.
    // Nibbles MSB-first: nib0 = byte0_high = (csum>>4)>>4 = csum>>8
    //                    nib1 = byte0_low  = (csum>>4) & 0xF
    //                    nib2 = byte1_high = (csum<<4 & 0xFF) >> 4 = csum & 0xF
    component csum_bits = Num2Bits(9);
    csum_bits.in <== csum;

    // chunks[32] = csum >> 8 (only 1 bit since csum < 2^9)
    chunks[32] <== csum_bits.out[8];

    // chunks[33] = (csum >> 4) & 0xF = bits [4..7] of csum
    var c33 = 0;
    for (var p = 0; p < 4; p++) c33 += csum_bits.out[4 + p] * (1 << p);
    chunks[33] <== c33;

    // chunks[34] = csum & 0xF = bits [0..3] of csum
    var c34 = 0;
    for (var p = 0; p < 4; p++) c34 += csum_bits.out[p] * (1 << p);
    chunks[34] <== c34;
}
