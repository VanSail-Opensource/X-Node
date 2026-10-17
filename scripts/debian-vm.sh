#!/bin/bash
set -euo pipefail
workspace=$(cd "$(dirname "$0")/.." && pwd)
cache_dir="$workspace/.cache/debian-vm"
run_dir=$(mktemp -d -t x-node-vm.XXXXXXXX)
qemu_pid=''
cleanup() {
    if [[ -n "$qemu_pid" ]]; then kill "$qemu_pid" 2>/dev/null || true; fi
    case "$run_dir" in /tmp/x-node-vm.*) rm -rf -- "$run_dir" ;; *) echo 'Unsafe VM cleanup path.' >&2 ;; esac
}
trap cleanup EXIT
mkdir -p "$cache_dir" "$workspace/dist"
image="$cache_dir/debian-13-genericcloud-amd64.qcow2"
if [[ ! -f "$image" ]]; then
    curl --fail --location --silent --show-error https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2 -o "$image"
    curl --fail --location --silent --show-error https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS -o "$cache_dir/SHA512SUMS"
    (cd "$cache_dir" && grep 'debian-13-genericcloud-amd64.qcow2$' SHA512SUMS | sha512sum -c -)
fi
cd "$workspace"
make build-amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/host-fixture ./cmd/host-fixture
ssh-keygen -q -t ed25519 -N '' -f "$run_dir/ssh-key"
public_key=$(cat "$run_dir/ssh-key.pub")
cat >"$run_dir/meta-data" <<'META'
instance-id: x-node-ci
local-hostname: x-node-fixture
META
cat >"$run_dir/user-data" <<USER
#cloud-config
ssh_pwauth: false
users:
  - name: fixture
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $public_key
write_files:
  - path: /etc/x-node-fixture-vm
    content: disposable
package_update: true
packages: [nftables, openssh-server, minisign, ca-certificates, iproute2, python3]
runcmd:
  - true
USER
cloud-localds "$run_dir/seed.img" "$run_dir/user-data" "$run_dir/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$run_dir/root.qcow2" 8G
accelerator=(-accel tcg -cpu max)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then accelerator=(-accel kvm -cpu host); fi
qemu-system-x86_64 "${accelerator[@]}" -m 1536 -smp 2 -drive "file=$run_dir/root.qcow2,format=qcow2,if=virtio" -drive "file=$run_dir/seed.img,format=raw,if=virtio" -netdev user,id=network,hostfwd=tcp:127.0.0.1:10022-:22 -device virtio-net-pci,netdev=network -display none -serial "file:$run_dir/console.log" &
qemu_pid=$!
ssh_args=(-i "$run_dir/ssh-key" -p 10022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -o BatchMode=yes)
ready=false
for attempt in $(seq 1 90); do
    if ssh "${ssh_args[@]}" fixture@127.0.0.1 'cloud-init status --wait >/dev/null'; then ready=true; break; fi
    sleep 2
done
if ! "$ready"; then cat "$run_dir/console.log"; exit 1; fi
scp -i "$run_dir/ssh-key" -P 10022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null dist/x-node-linux-amd64 dist/xnodectl-linux-amd64 dist/host-fixture deploy/x-node.service deploy/x-node-firewall.service fixture@127.0.0.1:/tmp/
ssh "${ssh_args[@]}" fixture@127.0.0.1 'sudo install -m 0755 /tmp/x-node-linux-amd64 /usr/local/bin/x-node && sudo install -m 0755 /tmp/xnodectl-linux-amd64 /usr/local/bin/xnodectl && sudo install -m 0644 /tmp/x-node.service /etc/systemd/system/x-node.service && sudo install -m 0644 /tmp/x-node-firewall.service /etc/systemd/system/x-node-firewall.service && sudo mkdir -p /etc/x-node /var/lib/x-node && printf "{\"master_url\":\"wss://127.0.0.1:65534/v1/agents/connect\",\"token\":\"disposable-fixture-token\"}" | sudo tee /etc/x-node/bootstrap.json >/dev/null && sudo chmod 0600 /etc/x-node/bootstrap.json && sudo systemctl daemon-reload && sudo install -D -m 0755 /tmp/host-fixture /usr/local/libexec/x-node-host-fixture && sudo /usr/local/libexec/x-node-host-fixture'

# A real reboot verifies restore ordering and that a fresh SSH connection works.
initial_boot=$(ssh "${ssh_args[@]}" fixture@127.0.0.1 'cat /proc/sys/kernel/random/boot_id')
ssh "${ssh_args[@]}" fixture@127.0.0.1 'sudo systemctl enable x-node.service && sudo systemctl reboot' || true
rebooted=false
for attempt in $(seq 1 90); do
    current_boot=$(ssh "${ssh_args[@]}" fixture@127.0.0.1 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
    if [[ -n "$current_boot" && "$current_boot" != "$initial_boot" ]]; then rebooted=true; break; fi
    sleep 2
done
if ! "$rebooted"; then cat "$run_dir/console.log"; exit 1; fi
ssh "${ssh_args[@]}" fixture@127.0.0.1 'sudo /usr/local/libexec/x-node-host-fixture --after-reboot'
