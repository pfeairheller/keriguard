# KERIGuard Sample Application

Local setup for testing KERIGuard daemon with Sentinel and Registrar integration


You will need 5 terminal windows (tmux helps a lot) to run all the needed components for this demonstration.

To get started, source the `env.sh` file in the scripts directory from the scripts directory.  After that, change directory back to the root of the repository.

These scripts assume you have writable directories in /usr/local/var/sentinel and /usr/local/var/wireguard.  To create them, run the following before the first time you run this demo:

```bash
mkdir /usr/local/var/sentinel
chown "${USER}" /usr/local/var/sentinel
mkdir /usr/local/var/wireguard
chown "${USER}" /usr/local/var/wireguard
```

For you will set up all the AIDs and OOBI connections:

```bash
./scripts/setup.sh
```

Now that the base AIDs are created, you need to launch your two sentinel daemons and tell them which AIDs to watch:


In 2 terminal windows, you will run the following commands:
- Terminal 1: `sentinel start --name registrar-sentinel --alias registrar-sentinel  --uxd --local  --export-dir /usr/local/var/sentinel/registrar`
- Terminal 2: `sentinel start --name keriguard-sentinel --alias keriguard-sentinel --uxd --local --export-dir /usr/local/var/sentinel/keriguard --registrar-url http://127.0.0.1:8080`

Now with those daemons running, you need to configure the watchers:

```bash
sentinel watcher add --name registrar --alias registrar --watcher registrar-sentinel --watched admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness
sentinel watcher add --name keriguard --alias keriguard --watcher keriguard-sentinel --watched admin --oobi http://127.0.0.1:5642/oobi/EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr/witness
```

Now you can launch the KERIGuard daemon and the Registrar daemon:

In the remaining 2 terminal windows (3 and 4), you will run the following commands:
- Terminal 3: `registrar start --name registrar --alias registrar --sentinel-export-dir /usr/local/var/sentinel/registrar/ -I EI6-tTwfonE2nKknuUkhkwRe-Op7kTYIeCUJcuuMUFUr`
- Terminal 4: `kg guardian start --name keriguard --alias keriguard --config-dir /usr/local/var/wireguard/ --sentinel /usr/local/var/sentinel/keriguard`


And finally, you can issue the interface credentials and publish them to the registrar:

```bash
./scripts/issue.sh
curl -XPUT http://localhost:8080/ -H "Content-Type: application/cesr" --data-binary @keriguard-wg0.cesr
curl -XPUT http://localhost:8080/ -H "Content-Type: application/cesr" --data-binary @keriguard-peer-wg0.cesr
curl -XPUT http://localhost:8080/ -H "Content-Type: application/cesr" --data-binary @keriguard-to-peer-connection.cesr

```

If it worked (🤞) you should have a `wg0.conf` in `/usr/local/var/wireguard/` that looks something like the following:

```conf
# Configuration: wg0
# Created: 2026-05-21T03:32:42.221679+00:00
# Modified: 2026-05-21T03:32:42.222196+00:00

[Interface]
# KERI AID: EMukoPLVfJ2sxulTtaAf4oTyNESAeoZGEkrEXT8JXjf0
PrivateKey = mPs0KKhcOfJUxkBV2IroFM7oTu8fFofY1N1J4Kk9jW0=
Address = 10.0.0.4/24
ListenPort = 5000

[Peer]
# KERI AID: EK9MXvIlVUcs9sztuX3oTJkBq-BqdKUxyLZmiOqXWZ8u
PublicKey = ZCQHDud5xZRskuHOnidRKr0jii5jfd1lt1NZUyIq8BQ=
AllowedIPs = 10.0.0.2/32
Endpoint = 147.182.240.249:43567

```


