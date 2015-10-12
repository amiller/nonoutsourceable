"""
Tools for prime field
"""

import random
import itertools
import binascii
import elgamal
import utils; reload(utils)
from utils import *
import math
from sha1 import sha1_fixed
"""
Weakly-nonoutsourceable puzzle scheme.
"""

# Protocol parameters
k = 160  # Main security parameter
Q1 = 10  # number of leaves to reveal during scratch
Q2 = 10  # number of leaves to reveal to sign payload

TREE1_HEIGHT = 11 # size of Tree1, O(log k)
TREE1_LEAVES = 2**(TREE1_HEIGHT-1)

# Compute at most this many hashes per circuit
HASHES_PER_CIRCUIT = 4
CIRCUITS_PER_BRANCH = int(math.ceil(float(TREE1_HEIGHT)/HASHES_PER_CIRCUIT))
ENC_BLOCKS_PER_CIRCUIT = int(math.ceil((1+HASHES_PER_CIRCUIT)*160/512.))
"""
For analysis:
1. Probability of finding a collision, two random samples of
Q2*4 leaves, out of TREE1_LEAVES, that overlap by at least Q2?

2. Probability of selecting Q1 leaves that overlap exactly?
"""

assert k%8 == 0, "this only works for multiple of bytes"


def genkey():
    leaves = [random_string(k/8) for _ in range(TREE1_LEAVES)]
    tree = merkle_tree(map(hash, leaves))
    return leaves,tree

import random
random.seed(213)
sk = genkey()

random.seed(12411)
puz = 2, random_string(k/8)

def scratch(puz, sk, m):
    assert len(m) == 20
    d, puzid = puz
    leaves,tree = sk
    root = tree[-1][0]

    # Draw a random nonce
    nonce = random_string(k/8)

    # Select Q1 branches
    h1 = sha1_fixed(rzfill(puzid + root + nonce, 64))
    qinds = select_hash(h1, Q1, TREE1_HEIGHT-1)

    leaves1 = [leaves[i] for i in qinds]
    branches1 = [merkle_select(tree, i) for i in qinds]

    # Merkle-Damgard hash
    # leaf [branch] ... leaf [branch]
    state = h1
    for leaf, branch in zip(leaves1, branches1):
        lb = [leaf] + branch
        for j in range(CIRCUITS_PER_BRANCH):
            lbh = lb[j*HASHES_PER_CIRCUIT:(j+1)*HASHES_PER_CIRCUIT]
            state = sha1_fixed(rzfill(state + ''.join(lbh), ENC_BLOCKS_PER_CIRCUIT*64))
    h2 = state
    # Check if winner!
    if not long(binascii.hexlify(h2), base=16) < 2**(k-d):
        return
    #print 'h2', binascii.hexlify(h2)

    # Use H(h2|m) to select 4*Q2 more leaves
    hm = h2
    q2inds = []
    iters = int(ceil(float(4*Q2)/(k/(TREE1_HEIGHT-1))))
    for i in range(iters):
        hm = hash(hm + m)
        #print 'hm', binascii.hexlify(hm)
        q2inds += select_hash(hm, (k/(TREE1_HEIGHT-1)), TREE1_HEIGHT-1)
    q2inds = q2inds[:Q2*4]

    #print "[scratch] qinds:", qinds, "q2inds:", q2inds

    # Choose the first Q2 (we have all of them)
    chosen = list(q2inds)
    random.shuffle(chosen)
    chosen = set(q2inds[:Q2])
    chosen = [q for q in q2inds if q in chosen]
    leaves2 = [leaves[i] for i in chosen]
    branches2 = [merkle_select(tree, i) for i in chosen]

    ticket = root, nonce, zip(leaves1+leaves2, branches1+branches2), chosen
    return ticket

# Ticket consists of: a root digest, a nonce, and a list of q+z branches
def verify_ticket(puz, ticket, m):
    # Parse ticket as root, nonce, branches
    d,puzid = puz
    root, nonce, leavesbranches, zinds = ticket

    # Check that root selects a set of q branches
    h1 = sha1_fixed(rzfill(puzid+root+nonce,64))
    qinds = select_hash(h1, Q1, TREE1_HEIGHT-1)

    # Compute hashtree digest over all the data in branches
    assert len(leavesbranches) == Q1+Q2
    assert len(qinds) + len(zinds) == Q1+Q2
    for ind,(leaf,branch) in zip(tuple(qinds)+tuple(zinds),leavesbranches):
        assert len(branch) == TREE1_HEIGHT-1
        assert merkle_check(hash(leaf), branch, root, ind)

    # Merkle Damgard hash over all leaves and branches
    state = h1
    for leaf, branch in leavesbranches[:Q1]:
        lb = [leaf] + branch
        for j in range(CIRCUITS_PER_BRANCH):
            lbh = lb[j*HASHES_PER_CIRCUIT:(j+1)*HASHES_PER_CIRCUIT]
            state = sha1_fixed(rzfill(state + ''.join(lbh), ENC_BLOCKS_PER_CIRCUIT*64))
    h2 = state

    assert long(binascii.hexlify(h2),16) < 2**(k-d)

    # Check that zinds are a Q2 subset of the 4Q2 chosen ones
    hm = h2
    iters = int(ceil(float(4*Q2)/(k/(TREE1_HEIGHT-1))))
    q2inds = []
    for i in range(iters):
        hm = hash(hm + m)
        q2inds += select_hash(hm, (k/(TREE1_HEIGHT-1)), TREE1_HEIGHT-1)
    q2inds = q2inds[:4*Q2]
    #print 'q2inds', q2inds
    assert len(zinds) == Q2
    #assert zinds == q2inds[:Q2]
    assert is_subset(zinds, q2inds)

    return True


random.seed(5151)
message = 'hi' + '\0'*18
ticket = None
while ticket is None:
    ticket = scratch(puz, sk, message)
assert ticket is not None
verify_ticket(puz, ticket, message)

"""
Strongly-Nonoutsourceable puzzle scheme
"""

def estimate_cost(Q1, Q2, h):
    n = 2**h
    merkle_hashes = h * (Q1 + Q2)
    chain_hashes = h*Q1
    encryptions = h*(Q1+Q2)/3 # Assume we can pack 3 160-bit values in 1 encryption
    gates_per_enc = 20817
    gates_per_hash = 23785
    gates_hash = gates_per_hash * (merkle_hashes + chain_hashes)
    gates_enc = gates_per_enc * encryptions
    gates_total = gates_enc + gates_hash
    print 'Cost Estimate'
    print 'Total hashes: %d' % (merkle_hashes + chain_hashes,)
    print 'Hash gates: %d' % (gates_hash,)
    print 'Encryption gates: %d' % (gates_enc,)
    print 'Total gates: %d' % (gates_total,)

    proofs = CIRCUITS_PER_BRANCH * (Q1+Q2) + 1
    bytes_per_proof = 288
    cipher_size = (Q1+Q2) * TREE1_HEIGHT * 20
    hmacs = 2 + CIRCUITS_PER_BRANCH*(Q1+Q2)

    print 'Proof size: ', proofs*bytes_per_proof + cipher_size + hmacs*20
    print 'Weak Proof size: ', (merkle_hashes + chain_hashes)*20, 'bytes'

def weak_estimate(Q1, Q2, h):
    #transactions per block 
    cost_per_dsa = 1.77e-3 # 1.77 ms for a dsa signature check
    merkle_hashes = h * (Q1 + Q2)
    chain_hashes = h*Q1
    

# Parameters

N_CIRCUITS = (Q1+Q2) * CIRCUITS_PER_BRANCH

random.seed(100312)
hmac_keys = [random_string(20) for _ in range(2+N_CIRCUITS)]

secret_exponent = random.randint(0,elgamal.q-1)

def shacal_encrypt(msg, ctr, key):
    # Counter mode
    assert len(key) == 20
    ciphertext = ''
    padtext = ''
    for i in range(int(math.ceil(len(msg)/20.))):
        block = msg[i*20:(i+1)*20]
        pad = hash(key + long_to_string(ctr,4))[:len(block)]
        padtext += pad
        c = long_to_string(string_to_long(pad) ^ string_to_long(block),len(block))
        ciphertext += c
        ctr += 1
    assert len(ciphertext) == len(msg)
    return ciphertext
        

def transform(puz, ticket, m, hmac_keys, secret_exponent):
    d, puzid = puz
    root, nonce, leavesbranches, chosen = ticket

    secret_value = elgamal.h_raised_to(secret_exponent)
    public_value = elgamal.g_raised_to(secret_exponent)
    enc_key = sha1_fixed(elgamal.group_element_to_string(secret_value))

    # A) Need to encrypt the root, nonce, leaves, and branches, in chunks
    # B) Need to make HMAC commitments to the internal state
    # C) Need to break the leavesQ1/branchesQ1 into chunks to be verified

    # Build an iterator over the randomness rather than counting for now
    assert len(hmac_keys) == 2+N_CIRCUITS

    # These need to be coalesced into group elements!
    ciphertexts = []
    assert len(leavesbranches) == Q1+Q2

    h1 = sha1_fixed(rzfill(puzid + root + nonce, 64))
    inds = select_hash(h1, Q1, TREE1_HEIGHT-1) + tuple(chosen)
    assert len(inds) == Q1 + Q2
    inds_s = rzfill(''.join(long_to_string(ind,2) for ind in inds), 48)

    # The first randomness is used as IV for the hashchain over leaves
    state = h1

    # Ciphertext accumulators, as well as the set of ciphertexts
    cipher_accs = []
    ciphertext_sets = []

    # Commitments to local state
    hmacs = []

    # Initialize hmacs with root, empty state/inds
    hmac = sha1_fixed(rzfill(hmac_keys[0] + h1 + '\0'*20,64))
    hmacs.append(hmac)

    # Commitments to glob
    hmacG = hash((hmac_keys[-1] + root + enc_key + inds_s))

    # Witnesses
    witnesses = []
    merkle_state = '\0'*20
    # First prepare the encryptions
    for b in range(Q1+Q2):
        leaf,branch = leavesbranches[b]
        leafbranch = [leaf] + branch
        ind = inds[b]
        for i in range(CIRCUITS_PER_BRANCH):
            # qhere is the number of branches to process here
            lbhere = leafbranch[HASHES_PER_CIRCUIT*i:HASHES_PER_CIRCUIT*(i+1)]
            stream = rzfill(state + ''.join(lbhere),ENC_BLOCKS_PER_CIRCUIT*64)

            # Update the state
            old_state = state
            if b < Q1: state = sha1_fixed(stream)
            # Encrypt using SHACAL, then pad to multiple of 512 bits
            stream = rzfill(''.join(lbhere),HASHES_PER_CIRCUIT*20)
            ciphertexts = shacal_encrypt(stream, b*HASHES_PER_CIRCUIT*CIRCUITS_PER_BRANCH + i*HASHES_PER_CIRCUIT, enc_key)
            assert len(ciphertexts) == HASHES_PER_CIRCUIT*20
            ciphertext_sets.append(ciphertexts)

            # Now we need to hash over the ciphertexts used in this circuit
            cipher_accs.append(sha1_fixed(rzfill(ciphertexts, ENC_BLOCKS_PER_CIRCUIT*64)))

            # Finally we need to prepare the auxiliary merkle tree information
            if i > 0:
                ind_copy = ind >> (i*HASHES_PER_CIRCUIT-1)
            else:
                ind_copy = ind

            old_merkle_state = merkle_state
            for j in range(HASHES_PER_CIRCUIT):
                if i*HASHES_PER_CIRCUIT + j >= TREE1_HEIGHT: continue
                sibling = lbhere[j]
                if i == 0 and j ==0:
                    merkle_state = hash(sibling) # It's actually the leaf
                else:
                    if not ind_copy % 2: # left node select, sibling to the right
                        merkle_state = hash(merkle_state + sibling)
                    else:
                        merkle_state = hash(sibling + merkle_state)
                    ind_copy >>= 1;
                if i*HASHES_PER_CIRCUIT + j == TREE1_HEIGHT-1:
                    assert merkle_state == root
            # Finally, we must collect the root, state, index accumulator, into
            # an hmac commitment
            
            hmac = sha1_fixed(rzfill(hmac_keys[b*CIRCUITS_PER_BRANCH+i+1] + state + merkle_state,64))
            hmacs.append(hmac)
            
            witness = (root, long_to_string((b<<16) + i,4), lbhere, hmac_keys[-1],
                       hmacs[-2], hmacs[-1], cipher_accs[-1], ciphertexts,
                       old_state, hmac_keys[b*CIRCUITS_PER_BRANCH+i], old_merkle_state,
                       state, hmac_keys[b*CIRCUITS_PER_BRANCH+i+1], enc_key, inds_s)
            witnesses.append(witness)

    # Verifier information
    verifier_data = ciphertext_sets, hmacs, public_value, hmacG

    # Witness information
    puzstr = long_to_string(d,4) + puzid
    last_witness = (root, nonce, hmacG, hmac_keys[-1],
                    hmac_keys[0],
                    state, inds_s, hmac_keys[-2],
                    hmacs[0], hmacs[-1], m, puzstr,
                    public_value,
                    secret_exponent, secret_value)
    witnesses.append(last_witness)
    return verifier_data, witnesses

ticket2, witness = transform(puz, ticket, message, hmac_keys, secret_exponent)

"""
Circuit Scheme 1
================
               v_input
                |
        H(hmac, hmac', ciphertexts, q1h[2] + qh[2] + i)
             /     \           |
          hmac     hmac'      H(ciphertexts)
           |           
HMAC(hmac_key, root, state, inds)


Circuit Scheme 2
================
           v_input
              |
      H(hmac0, hmacN, m, puz)

"""


# Check ticket
def vc_verify_ticket_full(puz, ticket, m, witnesses):
    d,puzid = puz
    ciphertext_sets, hmacs, public_value, hmacG = ticket

    assert len(witnesses) == N_CIRCUITS+1

    for b in range(Q1+Q2):
        for i in range(CIRCUITS_PER_BRANCH):
            ciphertexts = ciphertext_sets[b*CIRCUITS_PER_BRANCH+i]
            assert len(ciphertexts) == HASHES_PER_CIRCUIT*20
            cblocks = sha1_fixed(rzfill(ciphertexts, ENC_BLOCKS_PER_CIRCUIT*64))

            bi = (b<<16) + i
            bi_s = long_to_string(bi,4)
            v_input = hash((hmacs[b*CIRCUITS_PER_BRANCH+i] + hmacs[b*CIRCUITS_PER_BRANCH+i+1] + cblocks + bi_s + hmacG))

            assert vc_check_circuit_1(v_input, witnesses[b*CIRCUITS_PER_BRANCH+i])

    puzstr = long_to_string(d,4) + puz[1]
    v_input = hash(hmacs[0] + hmacs[-1] + m + puzstr + elgamal.group_element_to_string(public_value))
    assert vc_check_circuit_final(v_input, witnesses[-1])

# How to break down the entire scratch proof into separate components,
# which may be proven independently

def vc_check_circuit_1(v_input, witness):

    # Parse witness
    (root, bi_s, lbhere, hmacG_key,
     old_hmac, new_hmac, cblocks, ciphertexts,
     old_state, old_hmac_key, old_merkle_state,
     new_state, hmac_key, enc_key, inds_s) = witness

    b = string_to_long(bi_s) >> 16
    i = string_to_long(bi_s) & 0xffff

    # Recompute the global HMAC
    hmacG = hash(hmacG_key + root + enc_key + inds_s)

    # Open verifier input
    assert hash((old_hmac + new_hmac + cblocks + bi_s + hmacG)) == v_input

    # Check opening of state commitment
    old_hmac_check = sha1_fixed(rzfill(old_hmac_key + old_state + old_merkle_state,64))
    assert old_hmac_check == old_hmac

    # Check the encryption of branches
    stream = rzfill(''.join(lbhere),HASHES_PER_CIRCUIT*20)
    ciphertexts = shacal_encrypt(stream, b*HASHES_PER_CIRCUIT*CIRCUITS_PER_BRANCH+i*HASHES_PER_CIRCUIT, enc_key)
    assert cblocks == sha1_fixed(rzfill(ciphertexts, 64*ENC_BLOCKS_PER_CIRCUIT))

    # Check the updated hash state
    stream = rzfill(old_state + ''.join(lbhere),ENC_BLOCKS_PER_CIRCUIT*64)
    if b < Q1:
        new_state_check = sha1_fixed(stream)
    else:
        new_state_check = old_state
    assert new_state == new_state_check

    # Check the incremental merkle state
    ind = string_to_long(inds_s[2*b:2*(b+1)])
    if i > 0:
        ind_copy = ind >> (i*HASHES_PER_CIRCUIT-1)
    else:
        ind_copy = ind
    merkle_state = old_merkle_state
    for j in range(HASHES_PER_CIRCUIT):
        if i*HASHES_PER_CIRCUIT + j >= TREE1_HEIGHT: continue
        sibling = lbhere[j]
        if i == 0 and j ==0:
            merkle_state = hash(sibling) # It's actually the leaf
        else:
            if not ind_copy % 2: # left node select, sibling to the right
                merkle_state = hash(merkle_state + sibling)
            else:
                merkle_state = hash(sibling + merkle_state)
            ind_copy >>= 1;
            if i*HASHES_PER_CIRCUIT + j == TREE1_HEIGHT-1:
                assert merkle_state == root

    # Check opening of the new hmac commitment
    hmac = sha1_fixed(rzfill(hmac_key + new_state + merkle_state,64))
    assert hmac == new_hmac

    return True


def vc_check_circuit_final(v_input, witness):

    (root, nonce, hmacG, hmacG_key,
    first_hmac_key, 
    h2, inds_s, last_hmac_key,
    hmac0, hmacN, m, puzstr, 
     public_value,
     secret_exponent, secret_value) = witness

    d = string_to_long(puzstr[:4])
    puzid = puzstr[4:]

    # Recompute h1 and check indices
    h1 = sha1_fixed(rzfill(puzid + root + nonce,64))
    q1inds = select_hash(h1, Q1, TREE1_HEIGHT-1)

    # Recompute the entire inds hash
    hm = hash(h2 + m)
    q2inds = []
    iters = int(ceil(float(4*Q2)/(k/(TREE1_HEIGHT-1))))
    for i in range(iters):
        hm = hash(hm + m)
        q2inds += select_hash(hm, (k/(TREE1_HEIGHT-1)), TREE1_HEIGHT-1)

    inds = []
    for j in range(Q1+Q2):
        inds.append(string_to_long(inds_s[j*2:(j+1)*2]))
    inds = tuple(inds)
    assert inds[:Q1] == q1inds
    
    # TODO: check that Q2 is a subset of q2inds
    assert len(inds[Q1:Q1+Q2]) == Q2


    # Check the diffie hellman value for enc_key and secret_value
    gu = elgamal.g_raised_to(secret_exponent)
    hu = elgamal.h_raised_to(secret_exponent)
    assert secret_value == hu
    enc_key = sha1_fixed(elgamal.group_element_to_string(secret_value))
    print 'h1', binascii.hexlify(h1)
    # Check v_input
    assert hmac0 == sha1_fixed(rzfill(first_hmac_key + h1 + '\0'*20, 64))
    assert hmacN == sha1_fixed(rzfill(last_hmac_key + h2 + root, 64))

    assert hmacG == hash(hmacG_key + root + enc_key + inds_s)

    # Check the verifier input
    assert v_input == hash(hmac0 + hmacN + m + puzstr + elgamal.group_element_to_string(gu))

    # Check winning condition
    assert long(binascii.hexlify(h2),16) < 2**(k-d)
    
    return True

# Serialization for C reference implementation
def write_inputs(output_dir, puz, vcticket, witnesses):
    import os
    import scratch_pb2

    output_dir = output_dir + 'B_c%02d_h%02d_q1%02d_q2%02d' % (HASHES_PER_CIRCUIT, TREE1_HEIGHT, Q1, Q2)
    try:
        os.makedirs(output_dir)
    except OSError: pass # directory already exists

    class CircuitInput(object):
        def __init__(self, f):
            self.f = f
            self.wirecount = 0
        def write(self, s):
            assert len(s)%4 == 0, "Only writing multiples of 32 bits"
            for i in range(len(s)/4):
                b = s[i*4:(i+1)*4]
                ss = binascii.hexlify(b)
                self.f.write('%d %s\n' % (self.wirecount, ss))
                #print 'wrote:', self.wirecount
                self.wirecount += 1
        def close(self):
            self.f.write('%d 1\n' % (self.wirecount,))

    d,puzid = puz
    ciphertext_sets, hmacs, public_value, hmacG = vcticket

    for i,witness in enumerate(witnesses[:-1]):

        # Inner witness
        (root, bi_s, lbhere, hmacG_key,
         old_hmac, new_hmac, cblocks, ciphertexts,
         old_state, old_hmac_key, old_merkle_state,
         new_state, hmac_key, enc_key, inds_s) = witness

        # Local indices
        b = (string_to_long(bi_s) >> 16)
        z = (string_to_long(bi_s)) & 0xffff

        # Verifier input
        v_input = hash((hmacs[i] + hmacs[i+1] + cblocks + bi_s + hmacG))

        print 'inner witness[%d]: v_input:%s old_hmac:%s new_hmac:%s' % (
            i, binascii.hexlify(v_input),
            binascii.hexlify(old_hmac), binascii.hexlify(new_hmac))

        # Encryptions
        ciphertexts = ciphertext_sets[i]
        cblocks = sha1_fixed(rzfill(ciphertexts, 64*ENC_BLOCKS_PER_CIRCUIT))


        # Write the wire inputs file
        with open(os.path.join(output_dir,'wire_input_%02d.in' % i), 'w') as f:
            cf = CircuitInput(f)
            # Verifier's input
            cf.write(v_input)
            # Prover's inputs
            cf.write(root)
            cf.write(enc_key)
            assert len(inds_s) == 48
            cf.write(inds_s)
            cf.write(bi_s)
            cf.write(rzfill(''.join(lbhere), 20*(HASHES_PER_CIRCUIT)))
            print binascii.hexlify(rzfill(''.join(lbhere), 20*(HASHES_PER_CIRCUIT)))
            cf.write(old_hmac)
            cf.write(new_hmac)
            cf.write(hmacG)
            cf.write(old_merkle_state)
            cf.write(hmacG_key)
            cf.write(cblocks)
            cf.write(old_state)
            cf.write(old_hmac_key)
            cf.write(new_state)
            cf.write(hmac_key)
            cf.close()
            print "hmacG", binascii.hexlify(hmacG)

    # Final Witness
    for _ in [1]:
        (root, nonce, hmacG, hmacG_key,
         first_hmac_key, 
         h2, inds_s, last_hmac_key,
         hmac0, hmacN, m, puzstr, public_value,
         secret_exponent, secret_value) = witnesses[-1]

        gu = elgamal.g_raised_to(secret_exponent)
        hu = elgamal.h_raised_to(secret_exponent)
        assert public_value == gu
        assert secret_value == hu
        enc_key = sha1_fixed(elgamal.group_element_to_string(secret_value))

        # Check the verifier input
        v_input = hash(hmac0 + hmacN + m + puzstr + elgamal.group_element_to_string(gu))

        # Write the wire inputs file
        with open(os.path.join(output_dir,'wire_input_final.in'), 'w') as f:
            cf = CircuitInput(f)
            # Verifier's input
            #cf.write(v_input)
            assert len(v_input) == 20
            # Prover's inputs
            cf.write(hmacG)
            cf.write(hmac0)
            cf.write(hmacN)
            cf.write(m)
            assert len(m) == 20
            cf.write(puzstr)
            assert len(puzstr) == 24
            
            cf.write(root)
            cf.write(nonce)
            cf.write(hmacG_key)
            cf.write(first_hmac_key)
            cf.write(h2)
            assert len(inds_s) == 48
            cf.write(inds_s)
            cf.write(last_hmac_key)
            print 'root', binascii.hexlify(root)
            print 'nonce', binascii.hexlify(nonce)
            print 'hmac0', binascii.hexlify(hmac0)
            print 'hmacN', binascii.hexlify(hmacN)
            #cf.write(elgamal.group_element_to_string(gu))
            #assert len(elgamal.group_element_to_string(gu)) == 128
            cf.write(elgamal.group_element_to_string(hu))
            assert len(elgamal.group_element_to_string(hu)) == 128
            bitstring = bin(secret_exponent)[2:]
            bitstring = '0'*(512-len(bitstring)) + bitstring
            for bit in map(int,bitstring[::-1]):
                cf.write(long_to_string(bit,4))
            cf.close()

    # TODO: Write info for final value
