from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

"""
This is scary hand-rolled cryptography, because there aren't really any alternative
options in the python ecosystem. pyca/crytography probably won't add low-s support unless
openssl itself supports it and/or it gets standardised somewhere official.

Note for future maintainers (most likely me):
snarfed/arroba and MarshalX/atproto are using copy-pasted versions of this logic,
keep them in the loop if there are any important changes to be made.
"""


CURVE_ORDER = {
	# constant defined by NIST SP 800-186 - https://csrc.nist.gov/pubs/sp/800/186/final
	ec.SECP256R1: 0xFFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_BCE6FAAD_A7179E84_F3B9CAC2_FC632551,

	# constant defined by SECG SEC 2 - https://www.secg.org/sec2-v2.pdf
	ec.SECP256K1: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
}


def apply_low_s_mitigation(dss_sig: bytes, curve: ec.EllipticCurve) -> bytes:
	r, s = decode_dss_signature(dss_sig)
	n = CURVE_ORDER[type(curve)]
	if s > n // 2:
		s = n - s
	return encode_dss_signature(r, s)


def assert_dss_sig_is_low_s(dss_sig: bytes, curve: ec.EllipticCurve) -> None:
	_, s = decode_dss_signature(dss_sig)
	n = CURVE_ORDER[type(curve)]
	if s > n // 2:
		raise InvalidSignature("high-S signature")


def raw_sign(privkey: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
	r, s = decode_dss_signature(
		apply_low_s_mitigation(
			privkey.sign(data, ec.ECDSA(hashes.SHA256())),
			privkey.curve
		)
	)
	signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
	return signature


def keygen_p256() -> ec.EllipticCurvePrivateKey:
	return ec.generate_private_key(ec.SECP256R1())


def privkey_to_pem(privkey: ec.EllipticCurvePrivateKey) -> str:
	return privkey.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	).decode()


def privkey_from_pem(pem: str) -> ec.EllipticCurvePrivateKey:
	privkey = serialization.load_pem_private_key(pem.encode(), password=None)
	if not isinstance(privkey, ec.EllipticCurvePrivateKey):
		raise TypeError("unsupported key type")
	if not isinstance(privkey.curve, (ec.SECP256R1, ec.SECP256K1)):
		raise TypeError("unsupported key type")
	return privkey
