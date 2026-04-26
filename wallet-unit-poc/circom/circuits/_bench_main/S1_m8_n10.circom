pragma circom 2.2.3;

include "../show.circom";

component main {public[deviceKeyX, deviceKeyY]} = Show(10, 8, 15, 64);
