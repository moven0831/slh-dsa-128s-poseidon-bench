pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";   // Num2Bits, Bits2Num

// Decompose a single byte into 8 little-endian bits.
// Bit ordering matches FIPS 205 §3.1: byte b has bits b[0]..b[7]
// such that b = sum_i b[i] * 2^i (so bit 0 is the LSB).
template ByteToBitsLE() {
    signal input byte;
    signal output bits[8];
    component n2b = Num2Bits(8);
    n2b.in <== byte;
    for (var i = 0; i < 8; i++) {
        bits[i] <== n2b.out[i];
    }
}

// Decompose an array of bytes into bits (LSB-first per byte).
template BytesToBitsLE(nBytes) {
    signal input bytes[nBytes];
    signal output bits[8 * nBytes];
    component decomp[nBytes];
    for (var k = 0; k < nBytes; k++) {
        decomp[k] = ByteToBitsLE();
        decomp[k].byte <== bytes[k];
        for (var i = 0; i < 8; i++) {
            bits[8*k + i] <== decomp[k].bits[i];
        }
    }
}

// Decompose a byte into 8 BIG-endian bits (MSB-first).
// FIPS 205 §3.1 Algorithm "to_byte" / "to_int" treats byte arrays in
// big-endian order at the byte level; SHA-256 / Keccak internally use
// big-endian bit packing per byte. circomlib's Sha256 expects bits in
// big-endian byte-order (MSB of each byte first, i.e. bit 7..0).
template ByteToBitsBE() {
    signal input byte;
    signal output bits[8];
    component n2b = Num2Bits(8);
    n2b.in <== byte;
    // n2b.out is little-endian (bit i = 2^i coefficient).
    // Reverse to big-endian (bit 0 of output = MSB of byte).
    for (var i = 0; i < 8; i++) {
        bits[i] <== n2b.out[7 - i];
    }
}

// Decompose an array of bytes into bits, BIG-endian per byte.
template BytesToBitsBE(nBytes) {
    signal input bytes[nBytes];
    signal output bits[8 * nBytes];
    component decomp[nBytes];
    for (var k = 0; k < nBytes; k++) {
        decomp[k] = ByteToBitsBE();
        decomp[k].byte <== bytes[k];
        for (var i = 0; i < 8; i++) {
            bits[8*k + i] <== decomp[k].bits[i];
        }
    }
}

// Pack 8 bits (BIG-endian: bit 0 = MSB) into a byte.
// Companion to ByteToBitsBE.
template BitsBEToByte() {
    signal input bits[8];
    signal output byte;
    var s = 0;
    for (var i = 0; i < 8; i++) {
        s += bits[i] * (1 << (7 - i));
    }
    byte <== s;
}

// Pack a bit array (big-endian per byte) into bytes.
template BitsBEToBytes(nBytes) {
    signal input bits[8 * nBytes];
    signal output bytes[nBytes];
    component packers[nBytes];
    for (var k = 0; k < nBytes; k++) {
        packers[k] = BitsBEToByte();
        for (var i = 0; i < 8; i++) {
            packers[k].bits[i] <== bits[8*k + i];
        }
        bytes[k] <== packers[k].byte;
    }
}

// Range-check that an input is in [0, 255].
// Use this on every input that should be a byte; circom does NOT
// auto-range-check signal inputs.
template AssertByte() {
    signal input byte;
    component n2b = Num2Bits(8);
    n2b.in <== byte;
    // Num2Bits proves the value fits in 8 bits, i.e. byte in [0, 255].
}
