#include "scratch_circuit_2.h"
#include "sha1.h"

#ifndef QSP_NATIVE
#include "sha1.c"
#endif

void copy_u32(u32 *dst, u32 *src, u32 words) {
    int i;
    for (i = 0; i < words; i+=1) dst[i] = src[i];
}

void assert_digest_equal(u32 *a, u32 *b, struct Output *out) {
    int i;
    for (i = 0; i < 5; i+=1) 
        if (!(a[i] == b[i]))
            out->output_ok += 1;
}

void zero(u32 *mem, int n) {
    u32 i;
    for (i = 0; i < n; i+=1) mem[i] = 0;
}

extern print_hex_digest(const char *, const u32 *);

void outsource(struct Input *in, struct NIZKInput *witness, struct Output *out) {

    int i,j,k;

    out->output_ok = 0;

    u32 h1_open[16]; zero(h1_open, 16);
    copy_u32(&h1_open[ 0],&witness->puzstr[1], 5);
    copy_u32(&h1_open[ 5], witness->     root, 5);
    copy_u32(&h1_open[10], witness->    nonce, 5);
    u32 h1[5];
    sha1hash_fixed(h1_open, 1, h1);

    // TODO: Check that h1 can be parsed as inds_s

    // Generate the enc_key by hashing the group element
    u32 enc_key[5];
    sha1hash_fixed(witness->secret_value, 2, enc_key);
    
    // Check the verifier input
    u32 _v_input_open[16*4]; zero(_v_input_open, 16*4);
    copy_u32(&_v_input_open[ 0], witness->hmac0,  5);
    copy_u32(&_v_input_open[ 5], witness->hmacN,  5);
    copy_u32(&_v_input_open[10], witness->message, 5);
    copy_u32(&_v_input_open[15], witness->puzstr, 6);
    copy_u32(&_v_input_open[21], witness->public_value, 32);
    u32 v_input_check[5];
    sha1hash(_v_input_open, 3, 1696, v_input_check);
    assert_digest_equal(v_input_check, in->v_input, out);

    // Check opening of the first hmac commitment
    u32 hmac0_open[16*2]; zero(hmac0_open, 16*2);
    copy_u32(&hmac0_open[ 0], witness->first_hmac_key, 5);
    copy_u32(&hmac0_open[ 5], witness->          root, 5);
    copy_u32(&hmac0_open[10],                      h1, 5);
    copy_u32(&hmac0_open[15],                 enc_key, 5);
    copy_u32(&hmac0_open[20], witness->        inds_s,12);
    u32 hmac0_open_check[5];
    sha1hash_fixed(hmac0_open, 2, hmac0_open_check);
    assert_digest_equal(witness->hmac0, hmac0_open_check, out);

    // Check opening of the first hmac commitment
    u32 hmacN_open[16*2];
    copy_u32(&hmacN_open[ 0], witness->last_hmac_key, 5);
    copy_u32(&hmacN_open[ 5], witness->         root, 5);
    copy_u32(&hmacN_open[10], witness->           h2, 5);
    copy_u32(&hmacN_open[15],                enc_key, 5);
    copy_u32(&hmacN_open[20], witness->       inds_s,12);
    u32 hmacN_open_check[5];
    sha1hash_fixed(hmacN_open, 2, hmacN_open_check);
    assert_digest_equal(witness->hmacN, hmacN_open_check, out);

    // Check winning condition
    u32 d = witness->puzstr[0];
    u32 defless = 0;
    for (i = 0; i < 4; i += 1) {
        int target = 0;
        if (d >= (4-i)*32) {
            // 
        } else if (d < 4-i) {
            // 
        }
    }
}
