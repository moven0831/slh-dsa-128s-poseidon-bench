pragma circom 2.2.3;

// SLH-DSA-128s parameters (FIPS 205, Table 2).
// All values are compile-time constants; reference these (don't redefine).

function SLH_N()         { return 16;  }   // hash output size in bytes
function SLH_H()         { return 63;  }   // total hypertree height
function SLH_D()         { return 7;   }   // hypertree layers
function SLH_HPRIME()    { return 9;   }   // height of each XMSS layer
function SLH_A()         { return 12;  }   // FORS tree height (2^a leaves per tree)
function SLH_K()         { return 14;  }   // number of FORS trees
function SLH_LG_W()      { return 4;   }   // log2 of WOTS+ chain alphabet
function SLH_W()         { return 16;  }   // WOTS+ chain alphabet size
function SLH_M_BYTES()   { return 30;  }   // H_msg digest length
function SLH_LEN1()      { return 32;  }   // ceil(8n / lg_w)
function SLH_LEN2()      { return 3;   }   // floor(log2(len1*(w-1))/lg_w)+1
function SLH_LEN()       { return 35;  }   // len1 + len2 (WOTS+ chains per instance)

// Project-specific
function SLH_MSG_BYTES() { return 1024; }  // exactly 1024 B; we restrict KATs accordingly
function SLH_R_BYTES()   { return 16;   }  // randomizer length = n
function SLH_PK_BYTES()  { return 32;   }  // PK = PK.seed || PK.root, each n bytes
function SLH_SIG_BYTES() { return 7856; }  // R + SIG_FORS + SIG_HT

// FIPS 205 §10.2.1 digest decomposition for SLH-DSA-128s:
//   md       = ceil(k*a / 8) = 21 B  (FORS indices, 14×12 bits = 168 bits = 21 bytes)
//   idx_tree = ceil((h-h')/8) = 7 B  (XMSS tree index in the hypertree)
//   idx_leaf = ceil(h'/8) = 2 B      (leaf index within bottom-layer XMSS tree)
function SLH_MD_BYTES()       { return 21; }
function SLH_IDX_TREE_BYTES() { return 7;  }
function SLH_IDX_LEAF_BYTES() { return 2;  }
function SLH_IDX_TREE_BITS()  { return 54; }  // h - h' = 63 - 9 = 54
function SLH_IDX_LEAF_BITS()  { return 9;  }  // h' = 9

// ADRS type codes (FIPS 205 §4.2)
function ADRS_TYPE_WOTS_HASH()  { return 0; }
function ADRS_TYPE_WOTS_PK()    { return 1; }
function ADRS_TYPE_TREE()       { return 2; }
function ADRS_TYPE_FORS_TREE()  { return 3; }
function ADRS_TYPE_FORS_ROOTS() { return 4; }
function ADRS_TYPE_WOTS_PRF()   { return 5; }   // signing only; not used in verifier
function ADRS_TYPE_FORS_PRF()   { return 6; }   // signing only; not used in verifier

// ADRS encoded byte length per family (FIPS 205 §11.1, §11.2.2)
function ADRS_BYTES_SHA2()  { return 22; }
function ADRS_BYTES_SHAKE() { return 32; }
