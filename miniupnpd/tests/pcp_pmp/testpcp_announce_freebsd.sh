#!/bin/sh
# FreeBSD counterpart of testpcp_announce_linux.sh.
#
# On Linux the kernel chooses the multicast output interface from the socket's
# bound source address, which hides a daemon that never selects one.  FreeBSD
# routes by the default route, so an unscoped ANNOUNCE leaks out of the WAN.
# This boots a throwaway FreeBSD VM (QEMU), copies the checkout into it and
# runs freebsd/check-announce.sh there.
#
# Requires: qemu-system-x86_64, qemu-img, xz, curl, ssh, xorriso (or
# genisoimage/mkisofs).  KVM is used when /dev/kvm is usable.
#
# Environment:
#   PCP_TEST_FREEBSD_VERSION   FreeBSD release (default: newest release that
#                              has a cloud-init image, looked up at run time)
#   PCP_TEST_FREEBSD_CACHE     image cache dir (default: ~/.cache/miniupnpd-pcp-test)
#   PCP_TEST_FREEBSD_MEMORY    VM memory in MB (default: 2048)
#   PCP_TEST_FREEBSD_SSH_PORT  host port forwarded to the VM (default: 2222)
#   PCP_TEST_KEEP_VM=1         leave the VM running and keep its work dir
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd)
VERSION=${PCP_TEST_FREEBSD_VERSION:-}
BASE_URL=https://download.freebsd.org/releases/VM-IMAGES
CACHE=${PCP_TEST_FREEBSD_CACHE:-"$HOME/.cache/miniupnpd-pcp-test"}
MEMORY=${PCP_TEST_FREEBSD_MEMORY:-2048}
SSH_PORT=${PCP_TEST_FREEBSD_SSH_PORT:-2222}
KEEP_VM=${PCP_TEST_KEEP_VM:-0}

for tool in qemu-system-x86_64 qemu-img xz curl ssh ssh-keygen tar; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "$tool is required for the FreeBSD announce test." >&2
		exit 2
	fi
done
if command -v xorriso >/dev/null 2>&1; then
	mkseed() { xorriso -as mkisofs -quiet -output "$1" -volid cidata -joliet -rock "$2" >/dev/null 2>&1; }
elif command -v genisoimage >/dev/null 2>&1; then
	mkseed() { genisoimage -quiet -output "$1" -volid cidata -joliet -rock "$2" >/dev/null 2>&1; }
elif command -v mkisofs >/dev/null 2>&1; then
	mkseed() { mkisofs -quiet -output "$1" -volid cidata -joliet -rock "$2" >/dev/null 2>&1; }
else
	echo "xorriso, genisoimage or mkisofs is required to build the cloud-init seed." >&2
	exit 2
fi

WORK=$(mktemp -d)
QEMU_PID=
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$KEEP_VM" = 1 ]; then
		echo "Keeping VM (pid ${QEMU_PID:-none}); work dir $WORK; ssh -p $SSH_PORT -i $WORK/key freebsd@127.0.0.1" >&2
	else
		[ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true
		rm -rf "$WORK"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

image_name() { echo "FreeBSD-$1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2"; }
image_url() { echo "$BASE_URL/$1-RELEASE/amd64/Latest/$(image_name "$1").xz"; }

if [ -z "$VERSION" ]; then
	# Newest published release whose cloud-init image actually exists.
	for candidate in $(curl -fsS --retry 3 "$BASE_URL/" |
	    grep -o 'href="[0-9][0-9]*\.[0-9][0-9]*-RELEASE' | sed 's/href="//; s/-RELEASE//' |
	    sort -u -t. -k1,1nr -k2,2nr); do
		if curl -fsIL -o /dev/null "$(image_url "$candidate")"; then
			VERSION=$candidate
			break
		fi
	done
	if [ -z "$VERSION" ]; then
		echo "Could not find a FreeBSD release with a cloud-init image at $BASE_URL." >&2
		echo "Set PCP_TEST_FREEBSD_VERSION (for example 14.4) to choose one." >&2
		exit 1
	fi
fi
echo "Using FreeBSD $VERSION"
IMAGE_NAME=$(image_name "$VERSION")
IMAGE_URL=$(image_url "$VERSION")

mkdir -p "$CACHE"
if [ ! -f "$CACHE/$IMAGE_NAME" ]; then
	echo "Downloading $IMAGE_URL"
	curl -fL --retry 3 -o "$CACHE/$IMAGE_NAME.xz.part" "$IMAGE_URL"
	xz -d -c "$CACHE/$IMAGE_NAME.xz.part" >"$CACHE/$IMAGE_NAME.part"
	rm -f "$CACHE/$IMAGE_NAME.xz.part"
	mv "$CACHE/$IMAGE_NAME.part" "$CACHE/$IMAGE_NAME"
fi

# Throwaway overlay so the cached base image is never modified.
qemu-img create -q -f qcow2 -F qcow2 -b "$CACHE/$IMAGE_NAME" "$WORK/disk.qcow2" 10G
ssh-keygen -q -t ed25519 -N '' -f "$WORK/key"
mkdir "$WORK/seed"
cat >"$WORK/seed/meta-data" <<META
instance-id: miniupnpd-pcp-test
local-hostname: pcp-bsd
META
cat >"$WORK/seed/user-data" <<USER
#cloud-config
users:
  - name: freebsd
    groups: wheel
    shell: /bin/sh
    sudo: ALL=(ALL) NOPASSWD:ALL
    doas: permit nopass freebsd
    ssh_authorized_keys:
      - $(cat "$WORK/key.pub")
USER
mkseed "$WORK/seed.iso" "$WORK/seed"

ACCEL=tcg
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	ACCEL=kvm
else
	echo "No usable /dev/kvm; using slow software emulation." >&2
fi
qemu-system-x86_64 -machine accel=$ACCEL -cpu max -smp 2 -m "$MEMORY" \
	-display none -serial "file:$WORK/console.log" \
	-drive "file=$WORK/disk.qcow2,if=virtio" \
	-drive "file=$WORK/seed.iso,if=virtio,media=cdrom,readonly=on" \
	-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
	-device virtio-net-pci,netdev=n0 &
QEMU_PID=$!

SSH="ssh -p $SSH_PORT -i $WORK/key -o StrictHostKeyChecking=no \
 -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 freebsd@127.0.0.1"
echo "Waiting for the VM to accept SSH"
ready=0
attempt=0
while [ "$attempt" -lt 120 ]; do
	if ! kill -0 "$QEMU_PID" 2>/dev/null; then
		echo "QEMU exited early; console log:" >&2
		cat "$WORK/console.log" >&2
		exit 1
	fi
	if $SSH true 2>/dev/null; then
		ready=1
		break
	fi
	attempt=$((attempt + 1))
	sleep 5
done
if [ "$ready" -ne 1 ]; then
	echo "FreeBSD VM did not become reachable over SSH." >&2
	tail -40 "$WORK/console.log" >&2
	exit 1
fi

# Copy the tracked files plus uncommitted edits, without .git.
echo "Copying the checkout into the VM"
(cd "$REPO_ROOT" && git ls-files -co --exclude-standard -z | tar --null -T - -cf -) |
	$SSH 'sudo rm -rf /root/miniupnp && sudo mkdir -p /root/miniupnp && sudo tar -xf - -C /root/miniupnp'

$SSH 'cd /root/miniupnp && sudo sh miniupnpd/tests/pcp_pmp/freebsd/check-announce.sh'
