#include "scratch_circuitB_1.h"
#include "sha1.h"

#ifndef QSP_NATIVE
#include "sha1.c"
#endif

void zero(u32 *mem, int n) {
    u32 i;
    for (i = 0; i < n; i+=1) mem[i] = 0;
}

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

//#define PARAM_Z 0

#define STATE_FULLBLOCKS_PER_BRANCH ((TREE1_HEIGHT+1)*5/16)
#define STATE_BITS_PER_BRANCH ((TREE1_HEIGHT+1)*5*32)

#define CEIL_DIV(x, y) (((x) + (y) - 1) / (y))
#define ENC_BLOCKS_PER_CIRCUIT (CEIL_DIV((1+HASHES_PER_CIRCUIT)*160, 512))
#define CIRCUITS_PER_BRANCH (CEIL_DIV((TREE1_HEIGHT), HASHES_PER_CIRCUIT))

extern print_hex_digest(const char *, const u32 *);

void outsource(struct Input *in, struct Output *out) {

    int i,j,k;

    u32 *v_input = in->v_input;
    struct Witness *witness = &in->witness;

    out->output_ok = 0;

    /* NOTE: Ignore verifier input check for now, this suggests a scheme
      where the verifier input includes both hmacs */
    // Check opening of verifier's input
    /*
    u32 _v_input_open[16];
    copy_u32(&_v_input_open[ 0], witness->old_hmac, 5);
    copy_u32(&_v_input_open[ 5], witness->new_hmac, 5);
    copy_u32(&_v_input_open[10], witness-> cblocks, 5);
    _v_input_open[15] = witness->q1here_qhere_cnum;

    u32 v_input_check[5];
    //sha1hash(_v_input_open, 1, 544, v_input_check);
    sha1hash_fixed(_v_input_open, 1, v_input_check);
    assert_digest_equal(v_input_check, v_input, out);
    //copy_u32(&out->check_digest[0], v_input_check, 5);
    */

    u32 b = (witness->bi_s >> 16);
    u32 z = (witness->bi_s) & 0xffff;
    //u32 z = PARAM_Z;

    // Check opening of the old hmac commitment
    u32 hmac_open[16]; zero(hmac_open, 16);
    copy_u32(&hmac_open[ 0], witness->   old_hmac_key, 5);
    copy_u32(&hmac_open[ 5], witness->      old_state, 5);
    copy_u32(&hmac_open[10], witness->old_merkle_state,5);
    u32 hmac_open_check[5];
    sha1hash_fixed(hmac_open, 1, hmac_open_check);
    assert_digest_equal(witness->old_hmac, hmac_open_check, out);

    // Check opening of the globl hmac commitment
    u32 hmacG_open[16*2];
    copy_u32(&hmacG_open[ 0], witness->hmacG_key, 5);
    copy_u32(&hmacG_open[ 5], witness->     root, 5);
    copy_u32(&hmacG_open[10], witness->  enc_key, 5);
    copy_u32(&hmacG_open[15], witness->   inds_s,12);
    u32 hmacG_open_check[5];
    sha1hash(hmacG_open, 1, 864, hmacG_open_check);
    assert_digest_equal(witness->hmacG, hmacG_open_check, out);


#if 1
    // Check the updated hash state
    u32 stateleafbranch[ENC_BLOCKS_PER_CIRCUIT*16]; zero(stateleafbranch, ENC_BLOCKS_PER_CIRCUIT*16);
    for (j = 0; j < 5; j += 1) 
        stateleafbranch[j] = witness->old_state[j];

    for (i = 0; i < HASHES_PER_CIRCUIT; i += 1) {
        for (j = 0; j < 5; j += 1)
            stateleafbranch[(i+1)*5 + j] = witness->lbhere[i*5 + j];
        if (b < Q1)
            sha1hash_fixed(stateleafbranch, ENC_BLOCKS_PER_CIRCUIT, witness->old_state);
    }
    assert_digest_equal(witness->old_state, witness->new_state, out);
#endif

#if 1
    // Check the encryptions, using effectively SHACAL
    u32 ciphertext[ENC_BLOCKS_PER_CIRCUIT*16]; zero(ciphertext, ENC_BLOCKS_PER_CIRCUIT*16);
    for (j = 0; j < HASHES_PER_CIRCUIT; j += 1) {
        u32 padinput[16]; zero(padinput, 16);
        for (k = 0; k < 5; k += 1) padinput[k] = witness->enc_key[k];
        u32 ctr = b*HASHES_PER_CIRCUIT*CIRCUITS_PER_BRANCH + z*(HASHES_PER_CIRCUIT) + j;
        padinput[5] = ctr;
        u32 pad[5];
        sha1hash(padinput, 0, 6*32, pad);
        for (k = 0; k < 5; k += 1) {
            ciphertext[j*5+k] = witness->lbhere[j*5 + k] ^ pad[k];
        }        
    }
    u32 cblock_check[5];
    sha1hash_fixed(ciphertext, ENC_BLOCKS_PER_CIRCUIT, cblock_check);
    assert_digest_equal(witness->cblocks, cblock_check, out);    
#endif

#if 1
    // Copy the current indices here
    u32 ind;
    for (j = 0; j < 24; j += 1) {
        u32 ii;
        if ((j & 1) == 1) ii = witness->inds_s[j>>1] & 0xffff;
        else ii = (witness->inds_s[j>>1] >> 16) & 0xffff;
        if (j == b) ind = ii;
    }

    // Check all merkle tree branches
    u32 root_check[5];
    u32 merkle_state[5];
    for (k = 0; k < 5; k+=1) merkle_state[k] = witness->old_merkle_state[k];
    u32 buf[16];

    // Correct for the index
    u32 ind_copy = ind;
    u32 tt;
    if (z > 0) ind_copy = ind_copy >> (HASHES_PER_CIRCUIT - 1);
    for (tt = 1; tt < CIRCUITS_PER_BRANCH; tt += 1) {
        if (z > tt) ind_copy = ind_copy >> HASHES_PER_CIRCUIT;
    }
    for (j = 0; j < HASHES_PER_CIRCUIT; j += 1) {
        // Hash the leaf
        if ((z*HASHES_PER_CIRCUIT+j) < (TREE1_HEIGHT)) {
            u32 zj0;
            zj0 = 1;
            if (!(z == 0)) zj0 = 0;
            if (!(j == 0)) zj0 = 0;
            if (zj0 == 1) {
                for (k = 0; k < 5; k += 1)
                    buf[k] = witness->lbhere[5*j+k];
                sha1hash(buf, 0, 160, merkle_state);
            } else {
                u32 nodesibling[16];
                if ((ind_copy & 1) == 0) {
                    // Left branch selected, sibling to the right
                    for (k = 0; k < 5; k += 1) nodesibling[k+0] = merkle_state[k];
                    for (k = 0; k < 5; k += 1) nodesibling[k+5] = witness->lbhere[5*j+k];
                } else {
                    // Right branch select, sibling to the left
                    for (k = 0; k < 5; k += 1) nodesibling[k+0] = witness->lbhere[5*j+k];
                    for (k = 0; k < 5; k += 1) nodesibling[k+5] = merkle_state[k];
                }
                // Compute the next hash
                sha1hash(nodesibling, 0, 320, merkle_state);
                // Shift the index out
                ind_copy = ind_copy >> 1;
            }
            if (z*HASHES_PER_CIRCUIT + j == TREE1_HEIGHT-1) {
                for (k = 0; k < 5; k += 1) root_check[k] = merkle_state[k];
            assert_digest_equal(witness->root, root_check, out);
            }
        }
    }

    // Check opening of the next hmac commitment
    u32 new_hmac_open[16]; zero(new_hmac_open,16);
    copy_u32(&new_hmac_open[ 0], witness->    hmac_key, 5);
    copy_u32(&new_hmac_open[ 5], witness->   new_state, 5);
    copy_u32(&new_hmac_open[10],           merkle_state,5);
    u32 new_hmac_open_check[5];
    sha1hash_fixed(new_hmac_open, 1, new_hmac_open_check);
    assert_digest_equal(witness->new_hmac, new_hmac_open_check, out);

#endif
}
