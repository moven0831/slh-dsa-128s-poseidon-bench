pragma circom 2.2.3;

include "circomlib/circuits/poseidon.circom";   // Poseidon, PoseidonEx
include "circomlib/circuits/bitify.circom";

// Poseidon wrapper helpers for the non-standard Poseidon-SLH-DSA family.
//
// **NON-STANDARD; FOR BENCHMARKING ONLY.**
// circomlib's Poseidon constants are tuned for BN254. Compiled with
// `--prime secq256r1`, they survive as integers but the resulting
// Poseidon function is NOT a vetted instance. The R1CS structure and
// constraint count are unchanged from BN254; that's what we measure.

// Pack 16 bytes (LE) into one secq256r1 field element.
template PackBytes16ToFe() {
    signal input bytes[16];
    signal output fe;

    component to_bits[16];
    for (var i = 0; i < 16; i++) {
        to_bits[i] = Num2Bits(8);
        to_bits[i].in <== bytes[i];
    }
    var sum = 0;
    for (var i = 0; i < 16; i++) {
        sum += bytes[i] * (256 ** i);
    }
    fe <== sum;
}

// Unpack the low 16 bytes (LE) of a field element into a byte array.
template UnpackFeToBytes16() {
    signal input fe;
    signal output bytes[16];

    component n2b = Num2Bits(256);   // secq256r1 fits in 256 bits
    n2b.in <== fe;
    for (var k = 0; k < 16; k++) {
        var sum = 0;
        for (var b = 0; b < 8; b++) {
            sum += n2b.out[8 * k + b] * (1 << b);
        }
        bytes[k] <== sum;
    }
}

// PoseidonHash16(nInputs): hash nInputs field elements via circomlib
// Poseidon, return the low 128 bits as 16 bytes.
// nInputs must be ≤ 16 (circomlib limit; t=17).
template PoseidonHash16(nInputs) {
    signal input inputs[nInputs];
    signal output out[16];

    component p = Poseidon(nInputs);
    for (var i = 0; i < nInputs; i++) p.inputs[i] <== inputs[i];

    component unpack = UnpackFeToBytes16();
    unpack.fe <== p.out;
    for (var k = 0; k < 16; k++) out[k] <== unpack.bytes[k];
}

// PoseidonHash30(nInputs): two Poseidon calls with distinct domain-
// separation tags 0/1 prepended; concatenate low 128 + low 112 bits =
// 240 bits = 30 bytes.
template PoseidonHash30(nInputs) {
    signal input inputs[nInputs];
    signal output out[30];

    component p0 = Poseidon(nInputs + 1);
    component p1 = Poseidon(nInputs + 1);
    p0.inputs[0] <== 0;
    p1.inputs[0] <== 1;
    for (var i = 0; i < nInputs; i++) {
        p0.inputs[1 + i] <== inputs[i];
        p1.inputs[1 + i] <== inputs[i];
    }

    component unpack0 = UnpackFeToBytes16();
    component unpack1 = UnpackFeToBytes16();
    unpack0.fe <== p0.out;
    unpack1.fe <== p1.out;

    for (var k = 0; k < 16; k++) out[k] <== unpack0.bytes[k];
    for (var k = 0; k < 14; k++) out[16 + k] <== unpack1.bytes[k];
}

// Recursive binary-Merkle reduction of N field elements to 1, using
// Poseidon(2) at each tree node. Pads with zeros if N is not a power
// of 2. Cost: ceil(log2(N)) levels × ~ceil(N/2^level) Poseidon(2) per
// level = roughly N Poseidon(2) calls total.
template PoseidonReduce(N) {
    signal input inputs[N];
    signal output out;

    if (N == 1) {
        out <== inputs[0];
    } else {
        // Pair up; round up to even.
        var n_pairs = (N + 1) \ 2;
        signal pair_outs[n_pairs];
        component p[n_pairs];
        for (var i = 0; i < n_pairs; i++) {
            p[i] = Poseidon(2);
            p[i].inputs[0] <== inputs[2 * i];
            // For the last pair when N is odd, pair with zero.
            if (2 * i + 1 < N) {
                p[i].inputs[1] <== inputs[2 * i + 1];
            } else {
                p[i].inputs[1] <== 0;
            }
            pair_outs[i] <== p[i].out;
        }
        component rec = PoseidonReduce(n_pairs);
        for (var i = 0; i < n_pairs; i++) rec.inputs[i] <== pair_outs[i];
        out <== rec.out;
    }
}
