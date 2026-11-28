# Installing ss-agent on a node

`ss-agent` manages one `ss-server` instance. It must run as the same user as
`ss-server`, because it writes the server config and talks to the local control
socket.

Requirements:

- Linux x86-64
- `ss-server` 3.4.0 or newer
- systemd (recommended)

## Install the binary and unit

```sh
tar -xzf ss-agent_0.1.0_linux_amd64.tar.gz
cd ss-agent_0.1.0_linux_amd64

sudo install -m 0755 ss-agent /usr/local/bin/ss-agent
sudo install -m 0644 ss-agent.service /etc/systemd/system/ss-agent.service
```

Create the `shadowsocks` user if it does not already exist, and make sure the
directories used by the service are owned by that user:

```sh
sudo useradd --system --home /var/lib/shadowsocks-c --shell /usr/sbin/nologin shadowsocks || true
sudo mkdir -p /etc/shadowsocks-c /var/lib/shadowsocks-c/agent /run/shadowsocks-c
sudo chown -R shadowsocks:shadowsocks /etc/shadowsocks-c /var/lib/shadowsocks-c /run/shadowsocks-c
```

## Configure the agent

Copy `agent.json.example` to `/etc/shadowsocks-c/agent.json` and replace:

- `panel_url` with the panel URL;
- `enrollment_token` with the token shown when the node was created;
- `node_name` with the node name used in the panel.

Then:

```sh
sudo chown shadowsocks:shadowsocks /etc/shadowsocks-c/agent.json
sudo chmod 0600 /etc/shadowsocks-c/agent.json
sudo systemctl daemon-reload
sudo systemctl enable --now ss-agent
sudo journalctl -u ss-agent -f
```

`ss-agent` starts and supervises `ss-server`; do not run a separate
`ss-server` systemd unit on the same node.

After the agent connects, the panel node status changes to `online`. Client
links and node logs are available from the panel.
