#include "scratch_circuit_1.h"
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

#define TREE1_HEIGHT 3
#define STATE_FULLBLOCKS_PER_BRANCH ((TREE1_HEIGHT+1)*5/16)
#define STATE_BITS_PER_BRANCH ((TREE1_HEIGHT+1)*5*32)

//ENC_BLOCKS_PER_CIRCUIT = int(math.ceil(BRANCHES_PER_CIRCUIT * TREE1_HEIGHT * 160 / 512.))

#define CEIL_DIV(x, y) ((x) + (y) - 1) / (y)
#define ENC_BLOCKS_PER_CIRCUIT CEIL_DIV(BRANCHES_PER_CIRCUIT*TREE1_HEIGHT*160, 512)

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
    u32 qhere = (in->witness.q1here_qhere_cnum >> 16) & 0xff;
    u32 q1here = (in->witness.q1here_qhere_cnum >> 24) & 0xff;
    u32 cnum = (in->witness.q1here_qhere_cnum >> 8) & 0xff;

    // Check opening of the old hmac commitment
    u32 hmac_open[16*2];
    copy_u32(&hmac_open[ 0], witness->  old_hmac_key, 5);
    copy_u32(&hmac_open[ 5], witness->          root, 5);
    copy_u32(&hmac_open[10], witness->     old_state, 5);
    copy_u32(&hmac_open[15], witness->       enc_key, 5);
    copy_u32(&hmac_open[20], witness->        inds_s,12);
    u32 hmac_open_check[5];
    sha1hash_fixed(hmac_open, 2, hmac_open_check);
    assert_digest_equal(witness->old_hmac, hmac_open_check, out);

    // Check opening of the next hmac commitment
    u32 new_hmac_open[16*2];
    copy_u32(&new_hmac_open[ 0], witness->      hmac_key, 5);
    copy_u32(&new_hmac_open[ 5], witness->          root, 5);
    copy_u32(&new_hmac_open[10], witness->     new_state, 5);
    copy_u32(&new_hmac_open[15], witness->       enc_key, 5);
    copy_u32(&new_hmac_open[20], witness->        inds_s,12);
    u32 new_hmac_open_check[5];
    sha1hash_fixed(new_hmac_open, 2, new_hmac_open_check);
    assert_digest_equal(witness->new_hmac, new_hmac_open_check, out);

    // Copy the current indices here
    u32 indshere[BRANCHES_PER_CIRCUIT];
    u32 offset = BRANCHES_PER_CIRCUIT * cnum;
    for (i = 0; i < BRANCHES_PER_CIRCUIT; i+= 1) {
        for (j = 0; j < 48; j += 1) {
            u32 ii;
            if ((j & 1) == 1) ii = witness->inds_s[j>>1] & 0xffff;
            else ii = (witness->inds_s[j>>1] >> 16) & 0xffff;
            if (j == offset + i) indshere[i] = ii;
        }
    }

#if 1
    // Check the updated hash state
    u32 stateleafbranch[(STATE_FULLBLOCKS_PER_BRANCH+1)*16];
    for (i = 0; i < BRANCHES_PER_CIRCUIT; i += 1) {
        for (j = 0; j < 5; j += 1) 
            stateleafbranch[j] = witness->old_state[j];
        for (j = 0; j < 5*(TREE1_HEIGHT); j += 1)
            stateleafbranch[5+j] = witness->lbhere[i*5*TREE1_HEIGHT + j];
        if (i < q1here)
            sha1hash(stateleafbranch, STATE_FULLBLOCKS_PER_BRANCH, STATE_BITS_PER_BRANCH, witness->old_state);
    }
    assert_digest_equal(witness->old_state, witness->new_state, out);
#endif

#if 1
    // Check the encryptions, using effectively SHACAL
    for (i = 0; i < BRANCHES_PER_CIRCUIT; i+= 1) {
        u32 ciphertext[ENC_BLOCKS_PER_CIRCUIT*16];
        for (k = 0; k < ENC_BLOCKS_PER_CIRCUIT*16; k+= 1) ciphertext[k] = 0;

        for (j = 0; j < TREE1_HEIGHT; j += 1) {
            u32 padinput[16];
            for (k = 0; k < 16; k+= 1) padinput[k] = 0;
            for (k = 0; k < 5; k += 1) padinput[k] = witness->enc_key[k];
            u32 ctr = cnum * BRANCHES_PER_CIRCUIT * TREE1_HEIGHT + i * TREE1_HEIGHT + j;
            padinput[5] = ctr;
            u32 pad[5];
            sha1hash(padinput, 0, 6*32, pad);
            for (k = 0; k < 5; k += 1) 
                ciphertext[j*5+k] = witness->lbhere[i*5*TREE1_HEIGHT + j*5 + k] ^ pad[k];
        }
        u32 cblock_check[5];
        sha1hash_fixed(ciphertext, ENC_BLOCKS_PER_CIRCUIT, cblock_check);
        assert_digest_equal(witness->cblocks, cblock_check, out);
    }
#endif

#if 1
    // Check all merkle tree branches
    for (i = 0; i < BRANCHES_PER_CIRCUIT; i += 1) {
        u32 root_check[5];
        u32 ind = indshere[i];
        u32 node[5];
        u32 buf[16];

        // Start by hashing the leaf
        for (k = 0; k < 5; k += 1) 
            buf[k] = witness->lbhere[5*TREE1_HEIGHT*i+k];
        sha1hash(buf, 0, 160, node);

        //for (j = 0; j < TREE1_HEIGHT-1; j += 1) {
        for (j = 0; j < 4; j += 1) {
            u32 nodesibling[16];
            if ((ind & 1) == 0) {
                // Left branch selected, sibling to the right
                for (k = 0; k < 5; k += 1) nodesibling[k+0] = node[k];
                for (k = 0; k < 5; k += 1) nodesibling[k+5] = witness->lbhere[5*TREE1_HEIGHT*i+5 + 5*j+k];
            } else {
                // Right branch select, sibling to the left
                for (k = 0; k < 5; k += 1) nodesibling[k+0] = witness->lbhere[5*TREE1_HEIGHT*i+5 + 5*j+k];
                for (k = 0; k < 5; k += 1) nodesibling[k+5] = node[k];
            }
            // Compute the next hash
            sha1hash(nodesibling, 0, 320, node);
            // Shift the index out
            ind = ind >> 1;
        }
        for (k = 0; k < 5; k += 1) root_check[k] = node[k];
        assert_digest_equal(witness->root, root_check, out);
    }
#endif
}
