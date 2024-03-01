import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import millipds.jwt_monkeypatch as jwt

class JWTMonkeyPatchTestCase(unittest.TestCase):
	def setUp(self):
		# randomly generated test key
		self.priv_k1_pem = b"""-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgsPWcRtPwwHBFvujzyRUj
C7JlnnG3yOE1AxNGjbp8vtyhRANCAAQeOzdlRItXy4xfCEwm/FlwViqXzrXlV5r3
edC3qYgsCwXM9431jxbo4DJSutOrNVvZ2FIdBQWWMjWY9BlJykaV
-----END PRIVATE KEY-----"""
		self.priv_k1 = serialization.load_pem_private_key(self.priv_k1_pem, password=None)
		self.pub_k1 = self.priv_k1.public_key()
		self.pub_k1_pem = self.pub_k1.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		# likewise
		self.priv_r1_pem = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRFkAFd7bWnLoITfO
039Z8foMf5HJuV1NWdZ0Uw9A3KOhRANCAATphFD8cTEqoZ3DwSf0ymVZ8LMEz6+i
zVrbeSHCLN+xv33QrqEQj1GO18squ5a15I2NfJrovxap1LlJZFBl3cPL
-----END PRIVATE KEY-----"""
		self.priv_r1 = serialization.load_pem_private_key(self.priv_r1_pem, password=None)
		self.pub_r1 = self.priv_r1.public_key()
		self.pub_r1_pem = self.pub_r1.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		assert(type(self.priv_k1.curve) is ec.SECP256K1)
		assert(type(self.priv_r1.curve) is ec.SECP256R1)
	
	def test_k1_sign_verify(self):
		PAYLOAD = {"hello": "world"}
		for _ in range(32): # repeat to make sure we're not just just getting lucky
			token = jwt.encode(PAYLOAD, self.priv_k1_pem, algorithm="ES256K")
			decoded = jwt.decode(token, self.pub_k1_pem, algorithms=["ES256K"])
			self.assertEqual(decoded, PAYLOAD)
	
	def test_r1_sign_verify(self):
		PAYLOAD = {"hello": "world"}
		for _ in range(32): # repeat to make sure we're not just just getting lucky
			token = jwt.encode(PAYLOAD, self.priv_r1_pem, algorithm="ES256")
			decoded = jwt.decode(token, self.pub_r1_pem, algorithms=["ES256"])
			self.assertEqual(decoded, PAYLOAD)

	def test_k1_reject_high_s(self):
		high_s_k1_token = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJoZWxsbyI6IndvcmxkIn0.feGiEa50jQIhP9X_JhjUAAGrKMd4hyWGHRNVJCCoMZ3_OmsCf7NmoK_uqSnzRzazWCCuBUAoU1v5KAbmWoFZYQ"
		with self.assertRaisesRegex(InvalidSignature, "high-S"):
			jwt.decode(high_s_k1_token, self.pub_k1_pem, algorithms=["ES256K"])

	def test_r1_reject_high_s(self):
		high_s_r1_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.lsY80RX_GTMO2sNGAPm3s4girlFimMoHSkmnzr1TWbqYMPQjfYZhQTT9K2M6c_9O3qPoH7FCBSssXTGniq4RxQ"
		with self.assertRaisesRegex(InvalidSignature, "high-S"):
			jwt.decode(high_s_r1_token, self.pub_r1_pem, algorithms=["ES256"])

if __name__ == '__main__':
	unittest.main(module="tests.test_jwt_monkeypatch")
