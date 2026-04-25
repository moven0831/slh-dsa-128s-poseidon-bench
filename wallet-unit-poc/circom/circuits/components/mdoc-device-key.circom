pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/utils/array.circom";
include "../keyless_zk_proofs/arrays.circom";
include "../utils/utils.circom";

template MdocDeviceKeyExtractor(maxCredLen, maxPrefixLen) {
    signal input message[maxCredLen];
    signal input messageHash;
    signal input messageLength;
    signal input deviceKeyPrefix[maxPrefixLen];
    signal input deviceKeyPrefixLen;
    signal input deviceKeyPrefixPos;
    signal input yPrefixLen;

    signal output deviceKeyX;
    signal output deviceKeyY;

    CheckSubstrInclusionPoly(maxCredLen, maxPrefixLen)(
        message,
        messageHash,
        deviceKeyPrefix,
        deviceKeyPrefixLen,
        deviceKeyPrefixPos,
        1
    );

    signal xStart <== deviceKeyPrefixPos + deviceKeyPrefixLen;
    signal yStart <== xStart + 32 + yPrefixLen;
    signal keyEnd <== yStart + 32;


    var POS_BITS = log2Ceil(maxCredLen + 1);
    component endLe = LessEqThan(POS_BITS);
    endLe.in[0] <== keyEnd;
    endLe.in[1] <== messageLength;
    endLe.out === 1;

    component xShifter = VarShiftLeft(maxCredLen, 32);
    xShifter.in <== message;
    xShifter.shift <== xStart;

    signal xBytes[32];
    for (var i = 0; i < 32; i++) {
        xBytes[i] <== xShifter.out[i];
    }

    component yShifter = VarShiftLeft(maxCredLen, 32);
    yShifter.in <== message;
    yShifter.shift <== yStart;

    signal yBytes[32];
    for (var i = 0; i < 32; i++) {
        yBytes[i] <== yShifter.out[i];
    }

    deviceKeyX <== BytesToNumberBE(32)(xBytes);
    deviceKeyY <== BytesToNumberBE(32)(yBytes);
}
