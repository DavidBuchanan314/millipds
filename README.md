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
ExecStart=/opt/millipds/.venv/bin/millipds --args-go=here

[Install]
WantedBy=multi-user.target
```

Put this in `/etc/systemd/system/millipds.service`

```sh
sudo systemctl start millipds # make it start now
sudo systemctl enable millipds # make it start on every boot
sudo systemctl status millipds # check that it's running
```
