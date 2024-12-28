# millipds [WIP]
A from-scratch atproto PDS implementation that dreams of becoming "production grade" software (it isn't, yet).

millipds is a successor to [DavidBuchanan314/picopds](https://github.com/davidBuchanan314/picopds), which is even more minimalist, but hacky and no longer maintained.

It works to the extent that it can "federate" with the rest of the atproto network, but there are a lot of rough edges still. I wouldn't currently recommend using it for anything other than testing or experimentation (although, due to the nature of atproto, if you don't like it you can seamlessly migrate your whole account elsewhere). Until millipds reaches v1.0.0, I reserve the right to make breaking DB schema changes without providing a migration path.

It depends on [DavidBuchanan314/atmst](https://github.com/DavidBuchanan314/atmst) for implementing logic related to the Merkle Search Tree data structure, and [DavidBuchanan314/dag-cbrrr](https://github.com/DavidBuchanan314/dag-cbrrr) for DAG-CBOR parsing and serialisation.

See https://github.com/DavidBuchanan314/millipds/issues/12 for an incomplete list of differences between this implementation and the [reference implementation](https://github.com/bluesky-social/atproto/tree/main/packages/pds).

### Local dev install:

```sh
git clone https://github.com/DavidBuchanan314/millipds
cd millipds
python3 -m pip install -e .
```

### Dockerised dev install, via podman:

(note: I have no idea what I'm doing with this!)

```sh
podman build -f millipds_dev.dockerfile -t millipds_dev
podman run --rm -it -p 8123:8123 millipds_dev
```

### Production deployment on Ubuntu (and similar systems) [WIP]

See [./docs/DEPLOY.md](./docs/DEPLOY.md)
