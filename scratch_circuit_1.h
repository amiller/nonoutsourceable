#ifndef __SCRATCH_CIRCUIT_1__
#define __SCRATCH_CIRCUIT_1__

#ifdef QSP_NATIVE
typedef unsigned int u32;
#include <assert.h>
#define ASSERT(x) assert(x)
#else
#define u32 unsigned int
#define ASSERT(x) (x);
#endif


//#define BRANCHES_PER_CIRCUIT 1
//#define TREE1_HEIGHT 10

#include "sha1.h"

struct Witness {
    u32 root[5];
    u32 enc_key[5];
    u32 q1here_qhere_cnum;
    u32 inds_s[12];
    u32 lbhere[5*BRANCHES_PER_CIRCUIT*TREE1_HEIGHT];
    u32 old_hmac[5];
    u32 new_hmac[5];
    u32 cblocks[5];
    u32 old_state[5];
    u32 old_hmac_key[5];
    u32 new_state[5];
    u32 hmac_key[5];
};

struct Output {
    u32 output_ok;
    u32 check_digest[15];
};

struct Input {
    u32 v_input[5];
    struct Witness witness;
};

void outsource(struct Input *input, struct Output *output);

#endif // __SCRATCH_CIRCUIT_1__
