import requests
import os

PDS = "http://localhost:8123"
if 0:
	TEST_DID = "did:web:alice.test"
	TEST_HANDLE = "alice.test"
	TEST_PASSWORD = "alice_pw"
else:
	TEST_DID = "did:plc:bwxddkvw5c6pkkntbtp2j4lx"
	TEST_HANDLE = "local.dev.retr0.id"
	TEST_PASSWORD = "lol"

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
	json={"identifier": "example.invalid", "password": "wrongPassword123"},
)
assert not r.ok

r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": TEST_HANDLE, "password": "wrongPassword123"},
)
assert not r.ok


# valid logins

# by handle
r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": TEST_HANDLE, "password": TEST_PASSWORD},
)
print(r.text)
r = r.json()
print(r)
assert r["did"] == TEST_DID
assert r["handle"] == TEST_HANDLE
assert "accessJwt" in r
assert "refreshJwt" in r

# by did
r = s.post(
	PDS + "/xrpc/com.atproto.server.createSession",
	json={"identifier": TEST_DID, "password": TEST_PASSWORD},
)
r = r.json()
print(r)
assert r["did"] == TEST_DID
assert r["handle"] == TEST_HANDLE
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


r = s.get(PDS + "/xrpc/com.atproto.sync.getRepo", params={"did": TEST_DID})
assert r.ok


for i in range(10):
	r = s.post(PDS + "/xrpc/com.atproto.repo.applyWrites", headers=authn, json={
		"repo": TEST_DID,
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


blob = os.urandom(0x100000)
for _ in range(2): # test reupload is nop
	r = s.post(PDS + "/xrpc/com.atproto.repo.uploadBlob", data=blob, headers=authn|{"content-type": "blah"})
	res = r.json()
	print(res)
	assert r.ok

# get the blob refcount >0
r = s.post(PDS + "/xrpc/com.atproto.repo.createRecord", headers=authn, json={
	"repo": TEST_DID,
	"collection": "app.bsky.feed.post",
	"record": {"myblob": res}
})
print(r.json())
assert(r.ok)

r = s.get(PDS + "/xrpc/com.atproto.sync.getBlob", params={"did": TEST_DID, "cid": res["blob"]["ref"]["$link"]})
downloaded_blob = r.content
assert(downloaded_blob == blob)

r = s.get(PDS + "/xrpc/com.atproto.sync.getRepo", params={"did": TEST_DID})
assert r.ok
open("repo.car", "wb").write(r.content)

r = s.get(PDS + "/xrpc/com.atproto.sync.getRepo", params={"did": "did:web:nonexistent.invalid"})
assert not r.ok
assert r.status_code == 404

print("we got to the end of the script!")
