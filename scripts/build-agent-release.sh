#!/bin/sh
set -eu

version=${1:?usage: build-agent-release.sh VERSION [OUTPUT_DIR]}
out=${2:-dist}
arch=amd64
name="ss-agent_${version}_linux_${arch}"
pkg="${out}/${name}"
repo="github.com/Nikolay-Jiang/shadowsocks-web"

rm -rf "${pkg}"
mkdir -p "${pkg}"

go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build \
  -trimpath \
  -ldflags "-s -w -X ${repo}/internal/protocol.Version=${version}" \
  -o "${pkg}/ss-agent" ./cmd/ss-agent

"${pkg}/ss-agent" --version

cp deploy/systemd/ss-agent.service "${pkg}/ss-agent.service"
cp deploy/agent.json.example "${pkg}/agent.json.example"
cp docs/agent-install.md "${pkg}/agent-install.md"
cp README.md "${pkg}/README.md"

tar -C "${out}" -czf "${out}/${name}.tar.gz" "${name}"
(cd "${out}" && sha256sum "${name}.tar.gz" > checksums.txt)

echo "Built ${out}/${name}.tar.gz"
cat "${out}/checksums.txt"
