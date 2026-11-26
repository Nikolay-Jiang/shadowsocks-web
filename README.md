# shadowsocks-web

Web control plane for `shadowsocks-c` SIP023 users.

```text
browser -> ss-panel (HTTPS) <- ss-agent (outbound sync) -> ss-server
```

- `ss-panel` stores nodes, users and per-node PSKs in SQLite.
- `ss-agent` runs on each Linux node as the same user as `ss-server`. It writes
  `config.json` atomically, applies users-only changes through the local
  control socket, restarts for server settings, and reports traffic.
- Agents only make outbound HTTPS requests; no management port is exposed on
  nodes.

## Build

```sh
make
./bin/ss-panel --version
./bin/ss-agent --version
```

The binaries are static (`CGO_ENABLED=0`) and need no runtime libraries.

## Run the panel

```sh
export SS_PANEL_MASTER_KEY="$(openssl rand -base64 32)"
export SS_PANEL_PUBLIC_URL="https://panel.example.com"
export SS_PANEL_NAME="shadowsocks-web"
./bin/ss-panel -listen 127.0.0.1:8080 -data-dir ./data -secure-cookie
```

`SS_PANEL_PUBLIC_URL` is the `panel_url` written into the agent config shown
on each node page. It can also be passed as `-public-url`. If neither is set,
the panel derives it from the request (`Host` and `X-Forwarded-Proto`).

`SS_PANEL_NAME` changes the name shown in the top-left corner and browser
title. It can also be passed as `-name`. It defaults to `shadowsocks-web`.

## PSK migration

A user can be created with an optional initial PSK. When the user is assigned
to a node, a PSK entered in the assignment form overrides it; otherwise the
initial PSK is used; otherwise a new PSK is generated. This lets an existing
`serverPSK:userPSK` client keep its connection information when moving to the
panel.

Without `SS_PANEL_MASTER_KEY`, the panel creates `data/master.key` with mode
`0600`. Put the panel behind a TLS reverse proxy and use `-secure-cookie`.

Open `/setup` on first run, then create a node. The node page shows the agent
token once; store it in the agent config.

## Run an agent

```json
{
  "panel_url": "https://panel.example.com",
  "enrollment_token": "TOKEN_FROM_PANEL",
  "node_name": "hk-1",
  "data_dir": "/var/lib/shadowsocks-c/agent",
  "server_binary": "/usr/local/bin/ss-server",
  "server_config": "/etc/shadowsocks-c/config.json",
  "control_socket": "/run/shadowsocks-c/control.sock",
  "apply_mode": "supervisor"
}
```

```sh
./bin/ss-agent -c /etc/shadowsocks-c/agent.json
```

The agent supervises `ss-server`; systemd should run `ss-agent`, not
`ss-server`. See `deploy/systemd/ss-agent.service`.

## Reload behavior

- User additions, removals and PSK rotations use `reload` on the local socket;
  removed/rotated users are disconnected immediately.
- Port, method, server PSK and `require_identity` changes restart the server.
- The panel writes the `users` object; an absent field is never interpreted as
  "remove everyone".

## Development

```sh
make test
make vet
```
