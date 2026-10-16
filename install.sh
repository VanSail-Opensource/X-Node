#!/bin/bash
set -euo pipefail

REPOSITORY='VanSail-Opensource/X-Node'
PUBLIC_KEY='RWQ6HaDFAVc2u+yR4zuGuTn+wHojhxW7s7DxO1W22yj5r5yYwZgPt3qL'
version=''
master_url=''
token_stdin=false
start_service=true
while (($#)); do
    case "$1" in
        --version) version="$2"; shift 2 ;;
        --master-url) master_url="$2"; shift 2 ;;
        --token-stdin) token_stdin=true; shift ;;
        --no-start) start_service=false; shift ;;
        *) printf 'Unknown installer option: %s\n' "$1" >&2; exit 1 ;;
    esac
done
[[ $(id -u) == 0 ]] || { echo 'Run the installer as root.' >&2; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo 'X-Node installation requires apt-get.' >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo 'X-Node installation requires systemd.' >&2; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo 'Only amd64 and arm64 are supported.' >&2; exit 1 ;; esac
[[ -n "$master_url" || -f /etc/x-node/bootstrap.json ]] || { echo '--master-url is required for a fresh installation.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl minisign python3 nftables openssh-server
if [[ -z "$version" ]]; then
    version=$(curl --fail --silent --show-error --location "https://api.github.com/repos/$REPOSITORY/releases/latest" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert not d["draft"] and not d["prerelease"]; print(d["tag_name"])')
fi
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'A stable version tag is required.' >&2; exit 1; }
stage_dir=$(mktemp -d -t x-node-install.XXXXXXXX)
cleanup() { case "$stage_dir" in /tmp/x-node-install.*) rm -rf -- "$stage_dir" ;; *) echo 'Unsafe staging path; cleanup skipped.' >&2 ;; esac; }
trap cleanup EXIT
base="https://github.com/$REPOSITORY/releases/download/$version"
for asset in SHA256SUMS SHA256SUMS.minisig "x-node-linux-$arch" "xnodectl-linux-$arch"; do
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$base/$asset" -o "$stage_dir/$asset"
done
minisign -Vm "$stage_dir/SHA256SUMS" -P "$PUBLIC_KEY" -x "$stage_dir/SHA256SUMS.minisig" -q
[[ $(sed -n '3p' "$stage_dir/SHA256SUMS.minisig") == "trusted comment: version:$version" ]] || { echo 'Signed version differs.' >&2; exit 1; }
for binary in "x-node-linux-$arch" "xnodectl-linux-$arch"; do
    expected=$(awk -v name="$binary" '$2 == name { print $1 }' "$stage_dir/SHA256SUMS")
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || { echo 'Manifest entry missing or invalid.' >&2; exit 1; }
    actual=$(sha256sum "$stage_dir/$binary"); actual=${actual%% *}
    [[ "$actual" == "$expected" ]] || { echo 'Binary checksum mismatch.' >&2; exit 1; }
    chmod 0755 "$stage_dir/$binary"
    "$stage_dir/$binary" --version | python3 -c 'import json,sys; assert json.load(sys.stdin)["version"] == sys.argv[1]' "$version"
done
install -d -m 0700 /etc/x-node /var/lib/x-node
if [[ -n "$master_url" ]]; then
    if "$token_stdin"; then
        head -c 8192 | "$stage_dir/xnodectl-linux-$arch" configure --master-url "$master_url" --token-stdin
    else
        read -r -s -p 'Master token: ' token </dev/tty; printf '\n' >/dev/tty
        printf '%s' "$token" | "$stage_dir/xnodectl-linux-$arch" configure --master-url "$master_url" --token-stdin
        unset token
    fi
fi
# Installed systems use the signed, rollback-aware updater rather than replacing a live process here.
if [[ -x /usr/local/bin/xnodectl && -x /usr/local/bin/x-node ]]; then
    /usr/local/bin/xnodectl upgrade --version "$version"
    exit
fi
install -m 0755 "$stage_dir/x-node-linux-$arch" /usr/local/bin/x-node
install -m 0755 "$stage_dir/xnodectl-linux-$arch" /usr/local/bin/xnodectl
cat >/etc/systemd/system/x-node.service <<'UNIT'
[Unit]
Description=X-Node WebSocket-managed Xray agent
After=network-online.target nftables.service x-node-firewall.service
Wants=network-online.target x-node-firewall.service
StartLimitIntervalSec=0
[Service]
Type=notify
ExecStart=/usr/local/bin/x-node --config /etc/x-node/bootstrap.json
Restart=on-failure
RestartSec=5
TimeoutStartSec=0
TimeoutStopSec=30
WatchdogSec=60
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/x-node-firewall.service <<'UNIT'
[Unit]
Description=Restore confirmed X-Node firewall policy
After=local-fs.target systemd-sysctl.service nftables.service
Before=x-node.service
ConditionPathExists=/var/lib/x-node/firewall/policy.json
[Service]
Type=oneshot
ExecStart=/usr/local/bin/xnodectl firewall-restore
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable x-node.service x-node-firewall.service
if "$start_service"; then systemctl start x-node.service; fi
printf 'Installed X-Node %s. The first proxy configuration arrives over WebSocket.\n' "$version"
