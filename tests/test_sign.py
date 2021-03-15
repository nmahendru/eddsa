import pytest

import ed25519
from toyeddsa.eddsa import sign, enc_point, ed_mult, B, p, private_to_pub

def test_sign():
    import secrets

    k = secrets.randbelow(p())

    sig = sign(b"Nitin", k.to_bytes(32, 'little'))
    
    private = ed25519.SigningKey(k.to_bytes(32, 'little'))
    pub_derived = private.get_verifying_key()
    public = ed25519.VerifyingKey(enc_point(ed_mult(B, k)))
    assert public == pub_derived
    public.verify(sig, b"Nitin")

def test_enc_point():
    l = enc_point(B)
    print(l)

def test_vector_pub_pri():
    s = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    private = ed25519.SigningKey(bytes.fromhex(s))
    pub = private.get_verifying_key()
    pub_hex1 = pub.to_bytes().hex()
    public = enc_point(private_to_pub(bytes.fromhex(s)))
    pub_hex = public.hex()
    assert public.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"