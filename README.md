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

## Admin and Student SPAs, Caddy

The static Svelte apps are built and served directly by Caddy; no Node process
is needed at runtime. Build each app with Node.js 22.17 or newer:

```bash
cd apps/admin-app
npm ci
npm run build

cd ../student-app
npm ci
npm run check
npm run build
```

The builds are written to `apps/admin-app/build` and `apps/student-app/build`.
[`config/Caddyfile`](./config/Caddyfile) serves the admin app at
`192.168.1.11` and the student app at `students.cluster.castelli.local`; the
student hostname must resolve to the Caddy host. Configure a separate
Authentik proxy application for each hostname, both through the existing
outpost, and restrict them to `LAB_ADMIN` and `LAB_STUDENT` respectively.
Caddy strips untrusted `X-Remote-*` request headers and maps the verified
Authentik identity and groups to the headers consumed by FastAPI. Student
onboarding also requires the student's class group (for example `4A-INF`).
There is not yet a teacher frontend in this repository.

`AUTHENTIK_URL` must point to the Authentik outpost (for example
`http://192.168.1.71:9000`). After changing the Caddy service environment or
Caddyfile, validate the config and reload Caddy:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
```

The network dashboard reads authorized endpoints from `fwdd`'s nftables set
and active flows from `conntrack`. Install the updated daemon before restarting
`labctl-fwdd.service`; its startup reconciles firewall and route state, so plan
the restart accordingly. Install `conntrack` on the host to show active flows.

The backend requires exactly one role group (`LAB_STUDENT`, `LAB_TEACHER`, or
`LAB_ADMIN`). Proxmox pool membership is derived from the verified eight-digit
Authentik UID as `p-<uid>`. Proxmox ACLs must prevent students from changing
pool membership or moving containers to another pool; only an administrator
should be able to do that.