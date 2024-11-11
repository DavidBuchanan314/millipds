import requests

PDS = "http://localhost:8123"

s = requests.session()

# hello world
r = s.get(PDS + "/").text
print(r)
assert "Hello" in r

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
print(r.text)
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
assert r.ok

# bad auth
r = s.get(
	PDS + "/xrpc/com.atproto.server.getSession",
	headers={"Authorization": "Bearer " + token[:-1]},
)
print(r.text)
assert not r.ok

# bad auth
r = s.get(
	PDS + "/xrpc/com.atproto.server.getSession", headers={"Authorization": "Bearest"}
)
print(r.text)
assert not r.ok


r = s.get(PDS + "/xrpc/com.atproto.sync.getRepo", params={"did": "did:web:alice.test"})
assert r.ok


for i in range(100):
	r = s.post(PDS + "/xrpc/com.atproto.repo.applyWrites", headers=authn, json={
		"repo": "did:web:alice.test",
		"writes": [{
			"$type": "com.atproto.repo.applyWrites#create",
			"action": "create",
			"collection": "app.bsky.feed.like",
			"rkey": f"{i}-{j}",
			"value": {
				"blah": "test record"
			}
		} for j in range(10)]
	})
	print(r.json())
	assert r.ok


r = s.get(PDS + "/xrpc/com.atproto.sync.getRepo", params={"did": "did:web:alice.test"})
assert r.ok
open("repo.car", "wb").write(r.content)

print("we got to the end of the script!")
