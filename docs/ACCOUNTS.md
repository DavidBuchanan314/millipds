# Account Setup

Once you've followed the setup instructions in the main README, your PDS should be accessible on the internet. Loading the index page should show some ASCII art and a "Hello" message.

The next step is to create a user account.

These instructions assume you are already familiar with atproto's DID mechanisms. TODO: don't assume that!

Millipds does not hold did:plc rotation keys, and therefore it cannot make DID document updates on your behalf. This is good for security, and means that you can store your rotation keys offline.

Millipds *does* however need to hold a repo signing key.

Below, I assume you have two separate machines, the "server" (where the millipds server runs) and the "local machine". If you don't care about security (keeping rotation keys off the server) you can ignore that distinction and run all the commands on the server.

## New Account (with did:plc)

These instructions assume you're creating a user with handle `bob.example.com`, on a PDS at `https://pds.example.com` - replace them as appropriate!

On the **local machine**:
```sh
git clone https://github.com/DavidBuchanan314/millipds
cd millipds
python3 -m pip install . # install the millipds command (use a venv if you want, I guess)
./test_data/create_identity.sh bob.example.com https://pds.example.com https://plc.directory
```

Successful output should look something like this:
```
Generating keys...
Submitting genesis op to PLC...
OK

Created identity for bob.example.com at https://plc.directory/did:plc:shnwoo25lrvyq3gijyjdmmal

rotation key has been saved to bob.example.com_rotation_key.pem
repo signing key has been saved to bob.example.com_repo_key.pem
did:plc string has been logged to bob.example.com_did.txt

Please store the rotation key somewhere especially safe!
```

Store `*_rotation_key.pem` very securely, this is the key to your whole atproto identity (feel free to give it a more descriptive file name).

You'll need to copy `*_repo_key.pem` onto the server, however. (This key should also be kept secret, but if it's ever compromised or lost, you can replace it using the rotation key)

Now, on the **server**:
```sh
sudo -u millipds -s
source ~/.venv/bin/activate
millipds account create did:plc:shnwoo25lrvyq3gijyjdmmal bob.example.com --signing_key=bob.example.com_repo_key.pem
```

Edit the DID per the one you just generated above, and the handle and signing key path likewise.

You'll be prompted to enter a new password for the account, interactively. On success it should look something like this:

```
Password for new account: 
Confirm password: 
INFO:millipds.database:creating account for did=did:plc:shnwoo25lrvyq3gijyjdmmal, handle=bob.example.com
```

You also need to make sure the handle resolves. In this example, you'd create a TXT DNS record at `_atproto.bob.example` with value `did=did:plc:shnwoo25lrvyq3gijyjdmmal` (or use the .well-known method, see atproto docs. TODO: link)

At this point, the account is created, and you should be able to log in through a client like `bsky.app`.

You'll probably run into some error messages because the relay doesn't know about your PDS yet. This can be solved like so:

```sh
curl --json '{"hostname": "https://pds.example.com"}' "https://bsky.network/xrpc/com.atproto.sync.requestCrawl"
```

Finally, we need to emit an `#identity` event (probably an `#account` event too but millipds doesn't do that yet!!!). This can be done by heading to your settings in `bsky.app` and "changing" your handle to the value it already is (e.g. `bob.example.com`) - this tells millipds to emit an `#identity` event. (I'll make this part more automatic in the future)

Now, post something. If you're lucky, the relay and appview will pick it up, and now other people can see it. If not... have fun debugging...

## New Account (with did:web)

TODO (but it's conceptually not that different to did:plc, I bet you can figure it out!)

## Inbound Migration

TODO (millipds doesn't even support this yet, but one day it will)
