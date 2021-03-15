"""
https://en.wikipedia.org/wiki/EdDSA
https://tools.ietf.org/html/rfc8032#section-3
"""


def p():
    return pow(2, 255) - 19


def l():
    return pow(2, 252) + 27742317777372353535851937790883648493


d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
a = -1
B = [15112221349535400772501151409588531511454012693041857206046113283949847762202,
     46316835694926478169428394003475163141307993866256225615783033603165251855960]

n = 254
c = 3

def inv(nn):
    return pow(nn, p()-2, p())


def ed_add(p1, p2) -> (int, int):
    if not p1:
        return p2
    if not p2:
        return None
    x1 = p1[0]
    x2 = p2[0]
    y1 = p1[1]
    y2 = p2[1]
    denom = d * x1 * x2 * y1 * y2
    x = ((x1 * y2 + x2 * y1) * inv(1 + denom)) % p()
    y = ((y1 * y2 - a * x1 * x2) * inv(1 - denom)) % p()
    return x, y

def private_to_pub(k: bytes):
    s = calc_s(k)
    return ed_mult(B, s)

def calc_s(k: bytes):
    hk = hash_func(k)
    base1 = hk[:32]
    base1 = (base1[0] & 0b11111000).to_bytes(1, 'big') + base1[1:31] +  (0b01111111 & base1[31]).to_bytes(1, 'big')
    s = int.from_bytes(base1, 'little')
    
    return s

def ed_mult(point, s):
    s %= p()
    cache = point
    result = None
    while s:
        if s & 1:
            result = ed_add(result, cache) 
        cache = ed_add(cache, cache)
        s >>= 1
    return result


def enc_int(nn):
    return nn.to_bytes(32, 'little')


def enc_point(nn):
    y = nn[1].to_bytes(32, 'little')
    # lsb of x is the rightmost bit. can be obtained x & 1
    if nn[0] & 1:
        y = y[:31] + (y[31] | 0x80).to_bytes(1, 'little')
    return y


def dec_point(n_bytes):
    """
    a * x^2 + y^2 = 1 + d * x^2 * y^2
    """
    pass


def hash_func(input):
    import hashlib
    return hashlib.sha512(input).digest()


def sign(m: bytes, k: bytes):
    """
    Let R = [r]B and S = (r + H(ENC(R) || ENC(A) || PH(M)) * s)
    """
    hk = hash_func(k)
    r = int.from_bytes(hash_func(hk[32:] + m), 'little')
    R = ed_mult(B, r)
    s = calc_s(int.from_bytes(k, 'little'))
    hash_term = hash_func(enc_point(R) + enc_point(ed_mult(B, int.from_bytes(k, 'little'))) + m)
    S = ed_mult(B, (r + int.from_bytes(hash_term, 'little') * s))

    return enc_point(R) + enc_point(S)


