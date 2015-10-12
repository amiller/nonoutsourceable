from finite_fields.modp import IntegersModP
from finite_fields import polynomial
from finite_fields import finitefield
import itertools
import utils
import random
import math
import binascii

#p = 16798108731015832284940804142231733909759579603404752749028378864165570215949L # Pinocchio's prime
#p = # 21888242871839275222246405745257275088548364400416034343698204186575808495617 # Libsnark prime
u = 4
#q = 3441176304134516283521851883180660454185656235827678849281026614510147933478474098610174942770750446766178672910367817177330374059892050003431688950861L

# Nov 2014, Using Ahmed's numbers
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617L
q = 566003748421165623973140684210338877916630960782201693595769129706864925719318115473892932098619423042929922932476493069L
assert (p**u-1) % q == 0

Zp = IntegersModP(p)
Poly = polynomial.polynomialsOver(Zp).factory
#f = Poly([-2,0,0,0, 1])
f = Poly([-5,0,0,0, 1])
F = finitefield.FiniteField(p,u,f)

def powers_of_two_of(g):
    gx = g
    for i in itertools.count():
        yield gx
        gx *= gx

def _power(power_iter, exponent):
    gx = 1
    while exponent:
        if exponent%2: gx *= power_iter.next()
        else: power_iter.next()
        exponent /= 2
    return gx

# Find a generator of the subgroup of order q.
# Pick some element a, and raise it to the power of (p**8-1) / q
a = F([1,1,1,1])

if not '_powers_of_g' in globals():
    print 'Computing g and powers table of g'
    assert (p**u-1) % q == 0
    g = _power(powers_of_two_of(a), (p**u-1)/q)
    _powers_of_g = []
    for _,gx in zip(range(q.bit_length()), powers_of_two_of(g)):
        _powers_of_g.append(gx)

def g_raised_to(x):
    gx = 1
    i = 0
    while x:
        if x%2: gx *= _powers_of_g[i]
        x /= 2
        i += 1
    return gx

def h_raised_to(x):
    gx = 1
    i = 0
    while x:
        if x%2: gx *= _powers_of_h[i]
        x /= 2
        i += 1
    return gx

def keygen():
    def randint_long(high):
        # Rejection sample
        bs = int(math.ceil(high.bit_length()/8.))
        n = None
        while n is None:
            n = sum(random.randint(0,255)*256**i for i in range(bs))
            if n > high: n = None
        return n
    x = randint_long(q-1)
    print x, q-1
    return x, g_raised_to(x)

random.seed(12355)
if not 'h' in globals():
    print 'Generating crs (keypair)'
    x,h = keygen()
    _powers_of_h = []
    for _,gx in zip(range(q.bit_length()), powers_of_two_of(h)):
        _powers_of_h.append(gx)

def encrypt(m, y):
    # 1) Interpet m as an element of the group Fp8
    # 2) Compute g^y, h^y
    return (m,m)
    # Cheat!!!
    gy = g_raised_to(y)
    mhy = m * h_raised_to(y)
    return (gy,mhy)

def decrypt((gy,mhy)):
    return mhy * _power(powers_of_two_of(gy), x).inverse()

def pad_string(s):
    # Make string of the form needed here. This isn't perfectly secure..
    assert type(s) is str
    assert len(s) <= 128
    return s + '\0'*(128-len(s))

def string_to_group_element(m):
    assert type(m) is str
    assert len(m) == 128
    coeffs = []
    for i in range(u):
        c = int(binascii.hexlify(m[i*32:(i+1)*32]),16)
        coeffs.append(c)
    return F(coeffs)

def group_element_to_string(m):
    assert p.bit_length() == 254
    s = ''
    for c in m.poly.coefficients:
        s = s + binascii.unhexlify('%064x' % c.n)
    return s + (128-len(s))*'\0'
