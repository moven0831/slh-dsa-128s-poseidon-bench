pragma circom 2.2.3;

include "poseidon/hashes.circom";
include "common/slhdsa_verify.circom";

template MainPoseidon() {
    signal input pk[32];
    signal input msg[1024];
    signal input r[16];
    signal input sig_fors[14][13][16];
    signal input sig_ht[7][44][16];
    signal output valid;

    component v = SlhDsaVerify();
    for (var i = 0; i < 32; i++)   v.pk[i] <== pk[i];
    for (var i = 0; i < 1024; i++) v.msg[i] <== msg[i];
    for (var i = 0; i < 16; i++)   v.r[i] <== r[i];
    for (var i = 0; i < 14; i++) {
        for (var j = 0; j < 13; j++) {
            for (var b = 0; b < 16; b++) v.sig_fors[i][j][b] <== sig_fors[i][j][b];
        }
    }
    for (var j = 0; j < 7; j++) {
        for (var i = 0; i < 44; i++) {
            for (var b = 0; b < 16; b++) v.sig_ht[j][i][b] <== sig_ht[j][i][b];
        }
    }
    valid <== v.valid;
}
