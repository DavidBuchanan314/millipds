# millipds [WIP]
A successor to picopds

Dev install:

```
git clone https://github.com/DavidBuchanan314/millipds
cd millipds
python3 -m pip install -e .
```

Deployment on Ubuntu (and similar systems) [WIP]

```sh
# create unprivileged user
sudo adduser --system --shell /bin/false --home /opt/millipds millipds

# start a shell session under the new user
sudo -u millipds -s

# all commands below this point are run as the millipds user

# cd to its home dir (/opt/millipds in this case)
cd ~

# create a virtualenv (maybe this will prove unnecessary, but it probably doesn't hurt)
python3 -m venv .venv

# activate the virtualenv (this must be re-run every time you want to use it)
source .venv/bin/activate

# upgrade pip (maybe optional, again, probably doesn't hurt)
python3 -m pip install --upgrade pip

# install millipds
python3 -m pip install --upgrade millipds@git+https://github.com/DavidBuchanan314/millipds
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
ExecStart=/opt/millipds/.venv/bin/millipds --args-go=here
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
```

Put this in `/etc/systemd/system/millipds.service`

```
sudo systemctl start millipds
sudo systemctl status millipds
```
