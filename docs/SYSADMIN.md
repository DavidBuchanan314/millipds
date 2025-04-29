# Sysadmin Tips

Watch the millipds logs:

```sh
sudo journalctl -u millipds.service -f
```

Directly access the sqlite db:

```sh
sudo -u millipds /opt/millipds/.venv/bin/apsw /opt/millipds/data/millipds.sqlite3
```

This is useful because APSW likely ships a more bleeding-edge sqlite3 than the one supplied by your distro - accessing it like so will guarantee compatibility. If you're going to mess with the DB, I hope you know what you're doing!
