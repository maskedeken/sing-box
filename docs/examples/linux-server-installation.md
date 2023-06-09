#### Requirements

* Linux & Systemd
* Git
* C compiler environment

#### Install

```shell
git clone -b main https://github.com/SagerNet/sing-box
cd sing-box
./release/local/install_go.sh # skip if you have golang already installed
./release/local/install.sh
```

Edit configuration file in `/usr/local/etc/sing-box/config.json`

```shell
./release/local/enable.sh
```

#### Update

```shell
./release/local/update.sh
```

#### Other commands

| Operation | Command                                       |
|-----------|-----------------------------------------------|
| Start     | `sudo systemctl start sing-box`               |
| Stop      | `sudo systemctl stop sing-box`                |
| Kill      | `sudo systemctl kill sing-box`                |
| Restart   | `sudo systemctl restart sing-box`             |
| Logs      | `sudo journalctl -u sing-box --output cat -e` |
| New Logs  | `sudo journalctl -u sing-box --output cat -f` |
| Uninstall | `./release/local/uninstall.sh`                |