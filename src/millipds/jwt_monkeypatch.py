"""
extremely cursed: monkeypatch pyjwt to always produce low-s ECDSA signatures,
and likewise to only accept low-s ECDSA signatures.

In client code, replace "import jwt" with "import .jwt_monkeypatch as jwt"
"""

from jwt import *
from jwt import algorithms
from cryptography.hazmat.primitives.asymmetric import ec
from .crypto import apply_low_s_mitigation, assert_dss_sig_is_low_s

# "der_to_raw_signature" gets used during JWT signing, it's a convenient point to hook
_orig_der_to_raw_signature = algorithms.der_to_raw_signature

def _low_s_patched_der_to_raw_signature(der_sig: bytes, curve: ec.EllipticCurve) -> bytes:
	return _orig_der_to_raw_signature(apply_low_s_mitigation(der_sig, curve), curve)

algorithms.der_to_raw_signature = _low_s_patched_der_to_raw_signature


# "raw_to_der_signature" gets used during JWT verification, likewise, it's a convenient point to hook
_orig_raw_to_der_signature = algorithms.raw_to_der_signature

def _low_s_patched_raw_to_der_signature(raw_sig: bytes, curve: ec.EllipticCurve) -> bytes:
	der_sig = _orig_raw_to_der_signature(raw_sig, curve)
	assert_dss_sig_is_low_s(der_sig, curve)
	return der_sig

algorithms.raw_to_der_signature = _low_s_patched_raw_to_der_signature
