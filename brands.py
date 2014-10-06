#!/usr/bin/env python2
"""
Wrapper for libcred library

Copyright (c) 2014, Marsiske Stefan.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import ctypes, platform, struct, sys

if platform.system() == 'Windows':
    libcred = ctypes.cdll.LoadLibrary("libcred")
elif platform.system() == 'Darwin':
    libcred = ctypes.cdll.LoadLibrary('libcred.dylib')
else:
    libcred = ctypes.cdll.LoadLibrary("./libcred.so")

# TODO enable better keysizes
#CREDLIB_BRANDS_DEFAULT_KEY_SIZE = 2048
CREDLIB_BRANDS_DEFAULT_KEY_SIZE = 512

class DSA(ctypes.Structure):
    """
    helper class to represent DSA param structs from openssl
    """
    _fields_ = [("pad", ctypes.c_int),
                ("version", ctypes.c_long),
                ("write_params", ctypes.c_int),
                ("p", ctypes.c_void_p),
                ("q", ctypes.c_void_p),
                ("g", ctypes.c_void_p),
                ("pub", ctypes.c_void_p),
                ("priv", ctypes.c_void_p)]

brands_states = ['brands_undef',
                 'brands_init',
                 'brands_key',
                 # user states
                 'brands_req_pre',
                 'brands_req',
                 'brands_resp_pre',
                 'brands_resp',
                 'brands_cred',
                 # issuer state
                 'brands_chal',
                 # verifier state
                 'brands_show']

class Brands(ctypes.Structure):
    """
    typedef struct brands_s {
        brands_t state;
        bool_t issuer;		/* we own memory of g */
        DSA* params;
        BIGNUM** g;			/* issuer public */
        BIGNUM** y;			/* issuer private key */
        BIGNUM** x;			/* user attribs, x_0 is user private key */
        int num_attribs;		/* excluding private key alpha */
        bool_t* show;		/* remember what we showed/verified */
        BIGNUM* k;
        BIGNUM* alpha2;
        BIGNUM* alpha3;
        BIGNUM* h;
        BIGNUM* hp;
        BIGNUM* beta;
        BIGNUM* s;
        BIGNUM* t;
        BIGNUM* gamma;
        BIGNUM* u;
        BIGNUM* up;
        BIGNUM* v;
        BIGNUM* vp;
        BIGNUM* inv_alpha;
        BIGNUM** w;
        BIGNUM* a;
        BIGNUM* c;
        BIGNUM** r;
        BIGNUM* e;
        BIGNUM* M;
        BN_CTX* ctx;
    } BRANDS;
    """
    _fields_ = [("state", ctypes.c_uint),                    # enum (see brands_states)
                ("issuer", ctypes.c_bool),                   # bool
                ("dsa", ctypes.POINTER(DSA)),                # DSA*
                ("g", ctypes.POINTER(ctypes.c_void_p)),      # issuer public
                ("y", ctypes.POINTER(ctypes.c_void_p)),      # issuer private
                ("x", ctypes.POINTER(ctypes.c_void_p)),      # user attribs, x_0 is user private key
                ("num_attribs", ctypes.c_int),               # int
                ("show", ctypes.POINTER(ctypes.c_bool)),     # bool*
                ("k", ctypes.c_void_p),                      # BN*
                ("alpha2", ctypes.c_void_p),                 # BN*
                ("alpha3", ctypes.c_void_p),                 # BN*
                ("h", ctypes.c_void_p),                      # BN*
                ("hp", ctypes.c_void_p),                     # BN*
                ("beta", ctypes.c_void_p),                   # BN*
                ("s", ctypes.c_void_p),                      # BN*
                ("t", ctypes.c_void_p),                      # BN*
                ("gamma", ctypes.c_void_p),                  # BN*
                ("u", ctypes.c_void_p),                      # BN*
                ("up", ctypes.c_void_p),                     # BN*
                ("v", ctypes.c_void_p),                      # BN*
                ("vp", ctypes.c_void_p),                     # BN*
                ("inv_alpha", ctypes.c_void_p),              # BN*
                ("w", ctypes.POINTER(ctypes.c_void_p)),      # BN**
                ("a", ctypes.c_void_p),                      # BN*
                ("c", ctypes.c_void_p),                      # BN*
                ("r", ctypes.POINTER(ctypes.c_void_p)),      # BN**
                ("e", ctypes.c_void_p),                      # BN*
                ("M", ctypes.c_void_p),                      # BN*
                ("ctx", ctypes.c_void_p),                    # BN_CTX*
    ]

# BRANDS* BRANDS_new( void );
libcred.BRANDS_new.restype = ctypes.POINTER(Brands)
new = libcred.BRANDS_new

# int BRANDS_free( BRANDS* b );
libcred.BRANDS_free.argtypes = [ctypes.c_void_p]
free = libcred.BRANDS_free

# /* key setup calls */

# int BRANDS_key_generate( BRANDS* b, DSA* params, int key_size, int num_attribs );
libcred.BRANDS_key_generate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
key_generate = libcred.BRANDS_key_generate

# int BRANDS_key_set( BRANDS* b, BRANDS* issuer );
libcred.BRANDS_key_set.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
key_set = libcred.BRANDS_key_set

# /* user calls */

# int BRANDS_user_attrib_set( BRANDS* b, uint_t i, void* attr, int attr_len );
libcred.BRANDS_user_attrib_set.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_int]
def user_attrib_set(b, idx, attr):
    return libcred.BRANDS_user_attrib_set(b, idx, attr, len(attr))

# int BRANDS_user_request( BRANDS* b, byte** out, int* out_len );
def user_request(b):
    out = ctypes.c_void_p()
    outlen = ctypes.c_int()
    libcred.BRANDS_user_request(b, ctypes.byref(out), ctypes.byref(outlen))
    return ctypes.cast(out, ctypes.POINTER(ctypes.c_char))[:outlen.value]

# int BRANDS_user_response( BRANDS* b, byte* in, int in_len, byte** out, int* out_len );
def user_response(b, inp):
    out = ctypes.c_void_p()
    outlen = ctypes.c_int()
    libcred.BRANDS_user_response(b, inp, len(inp), ctypes.byref(out), ctypes.byref(outlen))
    return ctypes.cast(out, ctypes.POINTER(ctypes.c_char))[:outlen.value]

# int BRANDS_user_recv_cert( BRANDS *b, byte* in, int int_len );
def user_recv_cert(b, inp):
    return libcred.BRANDS_user_recv_cert(b, inp, len(inp))

# int BRANDS_user_attrib_show( BRANDS* b, uint_t attrib );
def user_attrib_show(b, attr):
    return libcred.BRANDS_user_attrib_show(b, attr)

# int BRANDS_user_send_show( BRANDS* b, bool_t* show, uint_t show_num, byte** out, int* out_len );
def user_send_show(b):
    out = ctypes.c_void_p()
    outlen = ctypes.c_int()
    libcred.BRANDS_user_send_show(b, None, 0, ctypes.byref(out), ctypes.byref(outlen))
    return ctypes.cast(out, ctypes.POINTER(ctypes.c_char))[:outlen.value]

# /* issuer calls */

# int BRANDS_issuer_challenge( BRANDS* b, byte* in, int in_len, byte** out, int* out_len );
def issuer_challenge(b, inp):
    out = ctypes.c_void_p()
    outlen = ctypes.c_int()
    libcred.BRANDS_issuer_challenge(b, inp, len(inp), ctypes.byref(out), ctypes.byref(outlen))
    return ctypes.cast(out, ctypes.POINTER(ctypes.c_char))[:outlen.value]

# int BRANDS_issuer_send_cert( BRANDS* b, byte* in, int in_len, byte** out, int* out_len );
def issuer_send_cert(b, inp):
    out = ctypes.c_void_p()
    outlen = ctypes.c_int()
    libcred.BRANDS_issuer_send_cert(b, inp, len(inp), ctypes.byref(out), ctypes.byref(outlen))
    return ctypes.cast(out, ctypes.POINTER(ctypes.c_char))[:outlen.value]

# /* verifier calls */

# int BRANDS_verifier_recv_show( BRANDS* b, byte* in, int in_len );
libcred.BRANDS_verifier_recv_show.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
def verifier_recv_show(b, inp):
    return libcred.BRANDS_verifier_recv_show(b, inp, len(inp))

# /* generic calls */

# int BRANDS_verify( BRANDS* b );
libcred.BRANDS_verify.argtypes = [ctypes.c_void_p]
verify = libcred.BRANDS_verify

# int BRANDS_precompute( BRANDS* b );
libcred.BRANDS_precompute.argtypes = [ctypes.c_void_p]
precompute = libcred.BRANDS_precompute

# int BRANDS_save( BRANDS* b, byte** out, int *out_len )
def save(b):
    out = ctypes.c_void_p()
    outlen = ctypes.c_int()
    ret = libcred.BRANDS_save(b, ctypes.byref(out), ctypes.byref(outlen))
    if ret <= 0: raise ValueError(ret)
    return ctypes.cast(out, ctypes.POINTER(ctypes.c_char))[:outlen.value]

# int BRANDS_load(BRANDS** out,  byte* in, int inlen )
def load(data):
    b = ctypes.c_void_p()
    res = libcred.BRANDS_load(ctypes.byref(b), data, len(data))
    if res <= 0: raise ValueError(res)
    return ctypes.cast(b, ctypes.POINTER(Brands))

# meh doesn't work, is a #define :/
#libcred.CREDLIB_free.argtypes = [ctypes.c_void_p]
#credlib_free = libcred.CREDLIB_free

# int CREDLIB_write_bn( byte* p, BIGNUM* bn )
libcred.CREDLIB_write_bn.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
write_bn = libcred.CREDLIB_write_bn

# int CREDLIB_write_bool_array_small( byte* p, const bool_t* ba, int len, int off )
libcred.CREDLIB_write_bool_array_small.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool), ctypes.c_int, ctypes.c_int]
write_bool_array_small = libcred.CREDLIB_write_bool_array_small

# int CREDLIB_read_bn( const byte* p, BIGNUM** bn )
libcred.CREDLIB_read_bn.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
read_bn = libcred.CREDLIB_read_bn

# BIGNUM** CREDLIB_BN_array_malloc( int size )
libcred.CREDLIB_BN_array_malloc.argtypes = [ctypes.c_int]
libcred.CREDLIB_BN_array_malloc.restype = ctypes.c_void_p
bn_array_malloc = libcred.CREDLIB_BN_array_malloc

# int CREDLIB_BN_array_free_fn( BIGNUM** bna, int size )
libcred.CREDLIB_BN_array_free_fn.argtypes = [ctypes.c_void_p, ctypes.c_int]
bn_array_free = libcred.CREDLIB_BN_array_free_fn

# int CREDLIB_read_bool_array_small( const byte* p, bool_t** bap, int* len, int off)
libcred.CREDLIB_read_bool_array_small.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_bool)), ctypes.POINTER(ctypes.c_int), ctypes.c_int]
read_bool_array_small = libcred.CREDLIB_read_bool_array_small

# helper functions

def req_attribs(cert):
    """
    takes a serialized output of user_request and outputs the requested attributes
    """
    attr_num = struct.unpack('>H', cert[:2])[0]
    i=2
    attribs = []
    for idx in xrange(attr_num):
        attribs.append((idx,read_bin(cert[i:])))
        i+=len(attribs[-1][1])+2
    return attribs

def disclosed_attribs(cert):
    """
    takes a serialized output of user_send_show and outputs the disclosed attributes
    """
    i=len(read_bin(cert))+2      # a
    i+=len(read_bin(cert[i:]))+2 # hp
    i+=len(read_bin(cert[i:]))+2 # up
    i+=len(read_bin(cert[i:]))+2 # vp
    attr_num = struct.unpack('>H', cert[i:i+2])[0]
    i+=2
    shows = [(ord(cert[i+o]) & (1 << (7-bit)))!=0 for o in xrange((attr_num+7)/8)
             for bit in xrange(8 if o+1<(attr_num+7)/8 else attr_num % 8)]
    i+=(attr_num+7)/8
    disclosed = []
    for idx, shown in enumerate([False] + shows):
        if shown:
            disclosed.append((idx,read_bin(cert[i:])))
            i+=len(disclosed[-1][1])+2
        else:
            _, tmp = (idx,read_bin(cert[i:]))
            i+=len(tmp)+2
    return disclosed

def show_attrs(cred):
    cred = cred.contents
    return [ (j, (bn2bin(cred.x[j])[2:] if cred.x[j] else None)) for j in xrange(1, cred.num_attribs)]

def display(cred):
    """
    prints the values of a credential to stdout
    """
    #print 'state', brands_states[int(struct.pack(">I", cred.state))]
    print >>sys.stderr, 'state', repr(struct.pack(">I", cred.state))
    print >>sys.stderr, 'issuer', repr(struct.pack(">?", cred.issuer))
           # DSA params
    print >>sys.stderr, 'p', repr( bn2bin(cred.dsa.contents.p))
    print >>sys.stderr, 'q', repr( bn2bin(cred.dsa.contents.q))
    print >>sys.stderr, 'g', repr( bn2bin(cred.dsa.contents.g))
    print >>sys.stderr, 'pub', repr(bn2bin(cred.dsa.contents.pub))
    print >>sys.stderr, 'priv', repr(bn2bin(cred.dsa.contents.priv))
    # g
    print >>sys.stderr, 'g',repr( [ bn2bin(cred.g[j]) if cred.g[j] else None for j in xrange(cred.num_attribs)])
    # y
    print >>sys.stderr, 'y',repr( [ bn2bin(cred.y[j]) if cred.y[j] else None for j in xrange(cred.num_attribs)]) if cred.y else None
    # x
    print >>sys.stderr, 'x',repr( [ bn2bin(cred.x[j]) if cred.x[j] else None for j in xrange(cred.num_attribs)]) if cred.x else None
    print  >>sys.stderr, 'num_attr', repr(struct.pack(">I", cred.num_attribs))
    print  >>sys.stderr, 'show', repr(packbools(cred.show.contents, cred.num_attribs) if cred.show else None)
    print  >>sys.stderr, 'k', repr(bn2bin(cred.k))
    print  >>sys.stderr, 'alp2', repr(bn2bin(cred.alpha2))
    print  >>sys.stderr, 'alp3', repr(bn2bin(cred.alpha3))
    print  >>sys.stderr, 'h', repr(bn2bin(cred.h))
    print  >>sys.stderr, 'hp', repr(bn2bin(cred.hp))
    print  >>sys.stderr, 'beta',repr(bn2bin(cred.beta))
    print  >>sys.stderr, 's',repr(bn2bin(cred.s))
    print  >>sys.stderr, 't', repr(bn2bin(cred.t))
    print  >>sys.stderr, 'gamma', repr(bn2bin(cred.gamma))
    print  >>sys.stderr, 'u', repr(bn2bin(cred.u))
    print  >>sys.stderr, 'up', repr(bn2bin(cred.up))
    print  >>sys.stderr, 'v', repr(bn2bin(cred.v))
    print  >>sys.stderr, 'vp', repr(bn2bin(cred.vp))
    print  >>sys.stderr, 'in_alpha', repr(bn2bin(cred.inv_alpha))
    print  >>sys.stderr, 'w', repr( [ bn2bin(cred.w[j]) for j in xrange(cred.num_attribs)]) if cred.w else None
    print  >>sys.stderr, 'a', repr(bn2bin(cred.a))
    print  >>sys.stderr, 'c', repr(bn2bin(cred.c))
    print  >>sys.stderr, 'r',repr( [ bn2bin(cred.r[j]) for j in xrange(cred.num_attribs)]) if cred.r else None
    print  >>sys.stderr, 'e', repr(bn2bin(cred.e))
    print  >>sys.stderr, 'M', repr(bn2bin(cred.M))

def new_cred(issuer):
    cred = new()
    key_set(cred,issuer)
    cred.contents.state = 2
    return cred

def new_req(issuer, attribs):
    cred = new_cred(issuer)
    # create some attributes
    for i, attr in enumerate(attribs):
        user_attrib_set(cred, i, attr)
    precompute(cred)
    # user -> issuer: request credential
    req = user_request(cred)
    return req, cred

def read_bin(data):
    size = struct.unpack('>H', data[:2])[0]
    return data[2:2+size]

def bn2bin(bn):
    buf = ctypes.create_string_buffer(4096)
    l = write_bn(buf,bn)
    return buf[:l]

def bin2bn(bin):
    ret = ctypes.c_void_p()
    l = read_bn(bin,ctypes.byref(ret))
    return ret, l

def packbools(bools, num_bools):
    buf = ctypes.create_string_buffer(512)
    l = write_bool_array_small(buf,bools, num_bools, 0)
    return buf[:l]

def test():
    """
    tests the bindings
    """
    #ctypes.c_int.in_dll(libcred, "verbose_flag").value = 1
    # create issuer
    issuer = new()
    key_generate(issuer, None, CREDLIB_BRANDS_DEFAULT_KEY_SIZE, 3)
    #display(issuer.contents)

    i2=load(save(issuer))
    #display(i2.contents)

    # create user
    cred = new()
    key_set(cred,i2)
    # create some attributes
    user_attrib_set(cred, 0, "20140920")
    user_attrib_set(cred, 1, "internet")
    user_attrib_set(cred, 2, "h.a.c.k.")
    precompute(cred)
    # user -> issuer: request credential
    resp1 = user_request(cred)
    #display(load(save(cred)).contents)
    #display(cred.contents)
    #print 'resp', repr(resp1)
    print 'requested attribs:', req_attribs(resp1)

    R, C = new_req(i2,["20140920",
                       "internet",
                       "h.a.c.k."])
    print '2nd req via i2', req_attribs(R)
    #display(C.contents)

    # issuer -> user: challenge
    chall = issuer_challenge(issuer,resp1)
    # user -> issuer: response
    precompute(cred)
    resp2 = user_response(cred, chall)
    #display(load(save(cred)).contents)
    #display(cred.contents)
    # issuer -> user: blind cert
    cert1 = issuer_send_cert(issuer, resp2)
    user_recv_cert(cred, cert1)
    #display(load(save(cred)).contents)
    #display(cred.contents)

    #display(issuer.contents)
    cred2 = load(save(cred))
    #display(cred2.contents)
    print 'your attributes in cred', show_attrs(cred)

    # optional verify yourself previous call already does
    #print verify(cred) > 0
    # showing some credentials
    #display(cred2.contents)
    user_attrib_show(cred2, 0)
    #user_attrib_show(cred2, 1)
    user_attrib_show(cred2, 2)
    #display(cred2.contents)
    show1 = user_send_show(cred2)
    #display(cred2.contents)
    print 'cred2: disclosed', disclosed_attribs(show1)
    # optional verify yourself
    #print 'is valid', verify(cred2) > 0
    # create some random verifier
    verifier = new()
    try:
        save(verifier)
    except ValueError, err:
        if str(err) == '-12':
            print '\o/ fails as expected, with', err
        else:
            print '/o\ fails unexpectedly, with', err
    key_set(verifier,issuer)
    #display(verifier.contents)
    print 'verifier: is valid', verifier_recv_show(verifier, show1) > 0
    free(issuer)
    free(i2)
    free(cred)
    free(C)
    free(cred2)
    free(verifier)
    #print 23, credlib_free( resp1 )
    #print 24, credlib_free( resp2 )
    #print 25, credlib_free( chall )
    #print 26, credlib_free( cert1 )
    #print 27, credlib_free( show1 )

if __name__ == '__main__':
    test()
