#include "scratch_circuitB_2.h"
#include "sha1.h"

#ifndef QSP_NATIVE
#include "sha1.c"
#endif

#define Q2 10

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

void select_hash(u32 *hash/*[5]*/, int n, u32 *inds/*[Q1]*/) {
    u32 i, j;
    u32 bits[160];
    for (i = 0; i < 5; i+=1) {
        u32 h = hash[i];
        for (j = 0; j < 32; j += 1) {
            bits[i*32+(31-j)] = h & 1;
            h = h >> 1;
        }
    }
    ASSERT(n*(TREE1_HEIGHT-1) <= 160)
    for (i = 0; i < n; i += 1) {
        inds[i] = 0;
        for (j = 0; j < (TREE1_HEIGHT-1); j+=1) {
            inds[i] |= bits[i*(TREE1_HEIGHT-1)+j] << (TREE1_HEIGHT-2-j);
        }
    }
}

#define CEIL_DIV(x, y) (((x) + (y) - 1) / (y))
#define INDS_PER_HASH (160/(TREE1_HEIGHT-1))
#define H2_ITERS CEIL_DIV(4*Q1, (INDS_PER_HASH))

void outsource(struct Input *in, struct NIZKInput *witness, struct Output *out) {

    int i,j,k;

    out->output_ok = 0;

    u32 h1_open[16]; zero(h1_open, 16);
    copy_u32(&h1_open[ 0],&in->puzstr[1], 5);
    copy_u32(&h1_open[ 5], witness->     root, 5);
    copy_u32(&h1_open[10], witness->    nonce, 5);
    u32 h1[5];
    sha1hash_fixed(h1_open, 1, h1);

    // Check that h1 can be parsed as inds_s
    u32 q1q2inds[48];
    for (i = 0; i < 24; i+=1) {
        u32 here = witness->inds_s[i];
        q1q2inds[2*i+0] = (here >> 16) & 0xffff;
        q1q2inds[2*i+1] = (here >>  0) & 0xffff;
    }
    // Next parse the inds out of H1 and check they match
    u32 q1check[Q1];
    select_hash(h1, Q1, q1check);
    for (i = 0; i < Q1; i+=1) {
        if (!(q1check[i] == q1q2inds[i])) out->output_ok += 1;
    }

    // Also check the inds from H2, and that q2 is a subset thereof
    u32 q2check[H2_ITERS*INDS_PER_HASH];
    u32 hm_input[16];
    u32 hm[5];
    for (k = 0; k < 5; k+=1) hm[k] = witness->h2[k];
    for (i = 0; i < H2_ITERS; i+= 1) {
        for (k = 0; k < 5; k+=1) hm_input[k] = hm[k];
        for (k = 0; k < 5; k+=1) hm_input[5+k] = in->message[k];
        sha1hash(hm_input, 0, 320, hm);
        select_hash(hm, INDS_PER_HASH, &q2check[i*INDS_PER_HASH]);
    }
    u32 q2_last = 0;
    for (i = 0; i < Q1; i += 1) {
        u32 qok = 1;
        u32 q = q1q2inds[Q1+i];
        for (j = 0; j < 4*Q1; j += 1) {
            u32 s = q2check[j];
            if (j >= q2_last) {
                if (q == s) {
                    q2_last = j+1;
                    qok = 0;
                }
            }
        }
        out->output_ok += qok;
    }

    // Generate the enc_key by hashing the group element
    u32 enc_key[5];
    sha1hash_fixed(witness->secret_value, 2, enc_key);

    // 
    
    // Check the verifier input
    /*u32 _v_input_open[16*4]; zero(_v_input_open, 16*4);
    copy_u32(&_v_input_open[ 0], witness->hmac0,  5);
    copy_u32(&_v_input_open[ 5], witness->hmacN,  5);
    copy_u32(&_v_input_open[10], witness->message, 5);
    copy_u32(&_v_input_open[15], witness->puzstr, 6);
    copy_u32(&_v_input_open[21], witness->public_value, 32);
    u32 v_input_check[5];
    sha1hash(_v_input_open, 3, 1696, v_input_check);
    assert_digest_equal(v_input_check, in->v_input, out);
    print_hex_digest("v_input_check", v_input_check);*/

    // Check opening of the first hmac commitment
    u32 hmac0_open[16]; zero(hmac0_open, 16);
    copy_u32(&hmac0_open[ 0], witness->first_hmac_key, 5);
    copy_u32(&hmac0_open[ 5],                      h1, 5);
    u32 hmac0_open_check[5];
    sha1hash_fixed(hmac0_open, 1, hmac0_open_check);
    assert_digest_equal(in->hmac0, hmac0_open_check, out);

    // Check opening of the first hmac commitment
    u32 hmacN_open[16]; zero(hmacN_open, 16);
    copy_u32(&hmacN_open[ 0], witness->last_hmac_key, 5);
    copy_u32(&hmacN_open[ 5], witness->           h2, 5);
    copy_u32(&hmacN_open[10], witness->        root, 5);
    u32 hmacN_open_check[5];
    sha1hash_fixed(hmacN_open, 1, hmacN_open_check);
    assert_digest_equal(in->hmacN, hmacN_open_check, out);

    // Check winning condition
    u32 d = in->puzstr[0];
    u32 defless = 1;
    for (i = 0; i < 4; i += 1) {
        for (j = 0; j < 32; j += 1) {
            if (i*32+j < d) {
                if ((witness->h2[i] >> (31-j)) == 1)
                    defless = 0;
            }
        }
    }
    if (defless == 0) out->output_ok += 1;

    // Check opening of the first hmac commitment
    u32 hmacG_open[16*2]; zero(hmacG_open, 16);
    copy_u32(&hmacG_open[ 0], witness->hmacG_key, 5);
    copy_u32(&hmacG_open[ 5], witness->     root, 5);
    copy_u32(&hmacG_open[10], enc_key,  5);
    copy_u32(&hmacG_open[15], witness->   inds_s,12);
    u32 hmacG_open_check[5];
    sha1hash(hmacG_open, 1, 864, hmacG_open_check);
    assert_digest_equal(in->hmacG, hmacG_open_check, out);
}
