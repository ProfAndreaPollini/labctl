# LabCtl

## Firewall daemon (`fwdd`)

The `labctl-fwdd` command runs the Linux firewall and routing daemon. Initialize
the SQLite schema first with `labctl-init-db`. The daemon expects the configured
nftables table and sets to exist, and uses `/usr/sbin/nft`, `/usr/sbin/ip`, and
optionally `/usr/sbin/conntrack`.

Run the daemon as root: it reconciles nftables and kernel routes, creates its
Unix socket (default `/run/fwdd/control.sock`), and assigns the socket to the
`fwdd-access` group. Socket access is additionally checked against the Unix UIDs
for `labwebapp` and `pvehook` (both configurable).

Database, socket, authorized users, and reconciliation interval can be changed
with `labctl-fwdd --help`. The database defaults to `/var/lib/labctl/state.db`,
shared with `labctl-init-db`.

## API service

The API service runs as the dedicated `labwebapp` account, which is the webapp
identity trusted by `fwdd`. Install the unit and enable it with:

```bash
sudo install -D -m 0644 deploy/systemd/labctl-api.service /etc/systemd/system/labctl-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now labctl-api.service
```

Stop any manually started Uvicorn process listening on `127.0.0.1:8000` before
starting the service. Optional API environment variables can be set in
`/etc/labctl/api.env`.

## Admin SPA and Caddy

The static Svelte app is built and served directly by Caddy; no Node process is
needed at runtime. Build it with:

```bash
cd apps/admin-app
# Use Node.js 22.17 or newer.
npm ci
npm run build
```

The build is written to `apps/admin-app/build`. Configure `ADMIN_DOMAIN` and
`AUTHENTIK_URL` in the Caddy service environment, then install
[`config/Caddyfile`](./config/Caddyfile) in the Caddy configuration. Caddy
protects the app and API with the Authentik outpost, strips untrusted
`X-Remote-*` request headers, and maps the verified Authentik identity and group
headers to the `X-Remote-*` headers consumed by FastAPI. Users must have the
`ADMIN` role in LabCtl (or be onboarded for the first time through an Authentik
group such as `LAB_ADMIN`) to use the administration API.

For an IP-based deployment, `ADMIN_DOMAIN` must be the exact site IP without a
scheme (for example `192.168.1.11`), and `AUTHENTIK_URL` must point to the
Authentik outpost (for example `http://192.168.1.71:9000`). After changing the
Caddy service environment or Caddyfile, validate the config and reload Caddy:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
```

The network dashboard reads authorized endpoints from `fwdd`'s nftables set
and active flows from `conntrack`. Install the updated daemon before restarting
`labctl-fwdd.service`; its startup reconciles firewall and route state, so plan
the restart accordingly. Install `conntrack` on the host to show active flows.