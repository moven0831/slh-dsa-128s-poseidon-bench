pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../keyless_zk_proofs/arrays.circom";
include "../keyless_zk_proofs/hashtofield.circom";
include "@zk-email/circuits/utils/array.circom";

template MdocValidUntil(maxCredLen) {
    signal input message[maxCredLen];
    signal input messageHash;
    signal input messageLength;
    signal input prefixPos;

    signal output validUntilDate;

    // CBOR: text(10) "validUntil" tag(0) text(20)
    var PREFIX_LEN = 13;
    var DATE_LEN = 10;
    signal prefix[PREFIX_LEN];
    prefix[0]  <== 0x6a;
    prefix[1]  <== 0x76;
    prefix[2]  <== 0x61;
    prefix[3]  <== 0x6c;
    prefix[4]  <== 0x69;
    prefix[5]  <== 0x64;
    prefix[6]  <== 0x55;
    prefix[7]  <== 0x6e;
    prefix[8]  <== 0x74;
    prefix[9]  <== 0x69;
    prefix[10] <== 0x6c;
    prefix[11] <== 0xc0;
    prefix[12] <== 0x74;

    CheckSubstrInclusionPoly(maxCredLen, PREFIX_LEN)(
        message,
        messageHash,
        prefix,
        PREFIX_LEN,
        prefixPos,
        1
    );

    var POS_BITS = log2Ceil(maxCredLen + 1);
    component endLe = LessEqThan(POS_BITS);
    endLe.in[0] <== prefixPos + PREFIX_LEN + DATE_LEN;
    endLe.in[1] <== messageLength;
    endLe.out === 1;

    component dateShifter = VarShiftLeft(maxCredLen, DATE_LEN);
    dateShifter.in <== message;
    dateShifter.shift <== prefixPos + PREFIX_LEN;

    signal ts[DATE_LEN];
    for (var i = 0; i < DATE_LEN; i++) {
        ts[i] <== dateShifter.out[i];
    }

    signal year  <== (ts[0] - 48) * 1000 + (ts[1] - 48) * 100 + (ts[2] - 48) * 10 + (ts[3] - 48);
    signal month <== (ts[5] - 48) * 10 + (ts[6] - 48);
    signal day   <== (ts[8] - 48) * 10 + (ts[9] - 48);

    validUntilDate <== year * 10000 + month * 100 + day;
}
