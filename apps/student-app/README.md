# LabCtl Student App

The static SvelteKit interface lets an authenticated student view their assigned
`/29`, reserve one of its five usable addresses for a Proxmox LXC VMID, and
remove an existing reservation.

## Development and build

Use Node.js 22.17 or newer:

```sh
npm ci
npm run check
npm run build
```

For local development, `vite.config.ts` proxies `/api/*` to
`http://127.0.0.1:8000` by default. Override the target with `LABCTL_API_URL`
when the API runs elsewhere. The dev server does not impersonate Caddy or add
trusted identity headers, so requests need to pass through the authenticated
Caddy host to exercise student login and authorization.

The static site is written to `build/` and should be served from the student
application's Authentik-protected host. The browser calls the same-origin
`/api/student/*` endpoints; it does not receive Proxmox credentials or identity
headers.

Authentik must provide the verified UID in `X-Authentik-Uid` and the role and
class groups in `X-Authentik-Groups`. The backend expects exactly one role group:
`LAB_STUDENT`, `LAB_TEACHER`, or `LAB_ADMIN`; students also need their class
group (for example `4A-INF`).
