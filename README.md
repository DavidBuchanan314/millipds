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

```sh
# create group for service socket access
sudo addgroup millipds-sock

# create unprivileged user
sudo adduser --system --shell /bin/false --home /opt/millipds millipds

# add the user to the group (leaving its primary group as the default)
sudo usermod -aG millipds-sock millipds

# start a shell session under the new user
sudo -u millipds -s

# all commands below this point are run as the millipds user

# create a virtualenv (maybe this will prove unnecessary, but it probably doesn't hurt)
python3 -m venv ~/.venv

# activate the virtualenv (this must be re-run every time you want to use it)
source ~/.venv/bin/activate

# all commands below this point are run inside the virtualenv

# upgrade pip (maybe optional, again, probably doesn't hurt)
python3 -m pip install --upgrade pip

# install millipds
python3 -m pip install --upgrade millipds@git+https://github.com/DavidBuchanan314/millipds
```

Upgrading:

```sh
sudo -u millipds -s
source ~/.venv/bin/activate
python3 -m pip install --upgrade --force-reinstall --no-cache-dir millipds@git+https://github.com/DavidBuchanan314/millipds
exit
sudo systemctl restart millipds
```

Create a systemd service

```
[Unit]
Description=millipds
After=network.target

[Service]
Type=simple
Restart=on-failure
User=millipds
WorkingDirectory=/opt/millipds
ExecStart=/opt/millipds/.venv/bin/millipds run --sock_path=/run/millipds/millipds.sock
RuntimeDirectory=millipds

[Install]
WantedBy=multi-user.target
```

TODO: put this file in the repo so it can be copied into place more easily.

Put this in `/etc/systemd/system/millipds.service`

Create a new nginx config:
```
upstream millipds {
	server unix:/run/millipds/millipds.sock fail_timeout=0;
}

server {
	listen 80;
	server_name millipds.test; # CHANGEME!

	location / {
		proxy_pass http://millipds;
		proxy_http_version 1.1;
		proxy_set_header Connection "upgrade";
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_read_timeout 1d;
		proxy_redirect off;
		proxy_buffering off;
		access_log off;
	}
}
```
TODO: is fail_timeout=0 sensible?

Put this in `/etc/nginx/sites-enabled/millipds`

Note: For a prod setup, you'll need to enable SSL. That's outside the scope of this guide, but one way is "once you have the service accessible via HTTP, use certbot"

Add the user that nginx runs under (`www-data`) to the `millipds-sock` group:

```sh
sudo adduser www-data millipds-sock
```

Start the service:

```sh
sudo systemctl start millipds # make it start now
sudo systemctl enable millipds # make it start on every boot
systemctl status millipds # check that it's running
sudo systemctl reload nginx # get nginx to see your new config
```

Useful command for watching the logs:
```sh
sudo journalctl -u millipds.service -f
```
