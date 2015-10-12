# Fairly general purpose utilities
import random
import itertools
from Crypto.Hash import SHA
import math
import binascii


# A compression function
def hash(x):
    bitlen = len(x) * 8
    #print 'hash: %d bytes' % len(x)
    assert bitlen % 32 == 0, 'only hash multiples of 32 bits'
    fullblocks = bitlen / 512
    assert bitlen % 512 > 0 and bitlen - fullblocks*512 <= 416, 'need to leave room for padding/size'
    return SHA.new(x).digest()

def string_to_long(s):
    assert type(s) is str
    import binascii
    return long(binascii.hexlify(s),16)

def long_to_string(n, b):
    assert type(n) in (int,long) and n < 2**(8*b)
    frm = '%0' + str(b*2) + 'x'
    return binascii.unhexlify(frm % n)

def pad_to_multiple(s, b):
    if len(s)%b > 0: s += '\0' * (len(s) - (len(s)/b)*b)
    return s

def rzfill(s, b):
    s += '\0' * (b - len(s))
    assert len(s) == b
    return s

def random_string(nbytes):
    return ''.join(chr(random.randint(0,255)) for _ in range(nbytes))

def select_hash(h,q,nbits):
    # Use randomness h to select q out of 2**n items
    hbits = len(h)*8
    assert q*nbits <= hbits, "parameters mismatch"
    # Parse h as bits, nbits at a time
    bytes = bytearray(h)
    bits = ''.join(bin(b)[2:].zfill(8) for b in bytes)
    r = []
    for i in range(q):
        r.append(int(bits[i*nbits:(i+1)*nbits],base=2))
    return tuple(r)

def is_subset(qitems, sup):
    # Assert that all items are distinct
    qlast = 0
    for q in qitems:
        qok = False
        for i,s in enumerate(sup):
            if q == s and i >= qlast:
                qlast = i+1
                qok = True
        if not qok: return False
    return True

def pad_stream_block(blocksize, data):
    # Assume blocksize is in bytes, pad with \0
    assert type(data) is str
    n = len(data)
    m = int(math.ceil(len(data) / float(blocksize)))
    blocks = []
    for i in range(m):
        here = min(n,blocksize)
        block = data[i*blocksize:i*blocksize+here]
        n -= here
        block += '\0' * (blocksize-here)
        assert len(block) == blocksize
        blocks.append(block)
    return blocks

def merkle_damgard(iv, blocks):
    assert iv is None or type(iv) is str and len(iv) == 20
    if iv is None:
        state = blocks[0]
        blocks = blocks[1:]
    else: state = iv
    for b in blocks:
        state = hash(state + b)
    return state

def merkle_digest(data):
    # Just the root digest
    return merkle_tree(data)[-1][0]

def merkle_tree(leaves):
    # Compute a merkle tree over leaves
    height = (len(leaves)-1).bit_length()+1
    assert 2**(height-1) == len(leaves) # balanced trees only
    layers = [list(leaves)]
    for level in range(1,height):
        d = []
        for i in range(len(layers[-1])/2):
            left = layers[-1][2*i+0]
            rght = layers[-1][2*i+1]
            d.append(hash(left+rght))
        layers.append(tuple(d))
    return tuple(layers)

def merkle_select(tree, ind):
    # Pick one of the branches
    assert 0 <= ind < len(tree[0])
    branch = []
    for i in range(len(tree)-1):
        # include the sibling hash
        sibling = tree[i][2*(ind/2)+(1-ind%2)]
        branch.append(sibling)
        ind /= 2
    return branch
        
def merkle_check(leaf, branch, root, ind):
    h = leaf
    for i,sibling in enumerate(branch):
        if not ind%2:
            h = hash(h + sibling)
        else: 
            h = hash(sibling + h)
        ind /= 2
    assert h == root
    return True

def merkle_check_debug(leaf, branch, root, ind):
    h = leaf
    for i,sibling in enumerate(branch):
        #print 'node', binascii.hexlify(h)
        if not ind%2:
            print 'left'
            h = hash(h + sibling)
        else: 
            print 'right'
            h = hash(sibling + h)
        #print 'sibling', binascii.hexlify(sibling)
        print 'h', binascii.hexlify(h)
        ind /= 2
    assert h == root
    return True

def test_merkle(data="abcdefgh"):
    tree = merkle_tree(data)
    root = merkle_digest(data)
    assert tree[-1][0] == root
    for i in range(len(data)):
        branch = merkle_select(tree, i)
        merkle_check(data[i], branch, root, i)
