import requests

PDS = "http://localhost:8123"

s = requests.session()

# hello world
r = s.get(PDS + "/").text
print(r)
assert r.startswith("Hello")

# describeServer
r = s.get(PDS + "/xrpc/com.atproto.server.describeServer")
print(r.json())

# no args
r = s.post(PDS + "/xrpc/com.atproto.server.createSession")
assert not r.ok

# invalid logins
r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": [], "password": "123"},
)
assert not r.ok

r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": "example.invalid", "password": "123"},
)
assert not r.ok

r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": "alice.test", "password": "123"},
)
assert not r.ok


# valid logins

# by handle
r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": "alice.test", "password": "alice_pw"},
)
r = r.json()
print(r)
assert r["did"] == "did:web:alice.test"
assert r["handle"] == "alice.test"
assert "accessJwt" in r
assert "refreshJwt" in r

# by did
r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": "did:web:alice.test", "password": "alice_pw"},
)
r = r.json()
print(r)
assert r["did"] == "did:web:alice.test"
assert r["handle"] == "alice.test"
assert "accessJwt" in r
assert "refreshJwt" in r

token = r["accessJwt"]
authn = {"Authorization": "Bearer " + token}

# good auth
r = s.get(PDS + "/xrpc/com.atproto.server.getSession", headers=authn)
print(r.json())
assert(r.ok)

# bad auth
r = s.get(PDS + "/xrpc/com.atproto.server.getSession", headers={"Authorization": "Bearer " + token[:-1]})
print(r.text)
assert(not r.ok)

# bad auth
r = s.get(PDS + "/xrpc/com.atproto.server.getSession", headers={"Authorization": "Bearest"})
print(r.text)
assert(not r.ok)
