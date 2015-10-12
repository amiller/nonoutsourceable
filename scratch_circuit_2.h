#ifndef __SCRATCH_CIRCUIT_2___
#define __SCRATCH_CIRCUIT_2__

#ifdef QSP_NATIVE
typedef unsigned int u32;
#include <assert.h>
#define ASSERT(x) assert(x)
#else
#define u32 unsigned int
#define ASSERT(x) (x);
#endif


#include "sha1.h"

struct NIZKInput {
    u32 root[5];
    u32 nonce[5];
    u32 first_hmac_key[5];
    u32 h2[5];
    u32 inds_s[12];
    u32 last_hmac_key[5];
    u32 hmac0[5];
    u32 hmacN[5];
    u32 message[5];
    u32 puzstr[6];
    u32 public_value[32];
    u32 secret_value[32];
    int secret_exponent[512]; // Expanded to be bits
};

struct Output {
    u32 output_ok;
    u32 check_digest[15];
};

struct Input {
    u32 v_input[5];
};

//void outsource(struct Input *input, struct Output *output);
void outsource(struct Input *input, struct NIZKInput *nizkinput, struct Output *output);

#endif // __SCRATCH_CIRCUIT_2__
