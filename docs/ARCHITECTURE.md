# A guided tour of the millipds codebase

The source is in `src/millipds/`.

The entrypoint for the main `millipds` command is `__main__.py`. CLI arg parsing happens here.

If you choose to launch the server, it calls out to `service.py`, which sets up an `aiohttp` application.

General-purpose routes are implemented right there in `service.py`, but others are handled in:

- `auth_oauth.py` - oauth stuff
- `atproto_repo.py` - `com.atproto.repo.*` endpoints
- `atproto_sync.py` - `com.atproto.sync.*` endpoints

`repo_ops.py` implements core repo commit logic - it's quite complex, even though [atmst](https://github.com/DavidBuchanan314/atmst) takes care of the actual MST operations.

`database.py` handles Database Stuff™, using `apsw` as an SQLite driver. There are also SQL queries littered throughout the rest of the codebase (no ORM...) The application is quite tightly coupled to SQLite-specific features (I've lost track of which ones).

`crypto.py` depends on `pyca/cryptography` and provides utilities for basic crypto stuff, including generating "low-S" signatures.
