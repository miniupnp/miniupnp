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
#   PCP_TEST_OUT_DIR           where check.log, summary.txt, console.log and the
#                              VM's announce-test/ logs are saved (default:
#                              <repo>/.tmp/ci/out/freebsd/announce)
#   PCP_TEST_KEEP_VM=1         leave the VM running and keep its work dir
#
# The first run boots the downloaded image once, installs gmake/pkgconf/rsync (and
# the libpfctl.h header on FreeBSD 15) and caches the result as
# prepared-<version>.qcow2 in the cache dir; later runs boot a throwaway
# overlay on it.  Delete that file to rebuild it.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd)
VERSION=${PCP_TEST_FREEBSD_VERSION:-}
BASE_URL=https://download.freebsd.org/releases/VM-IMAGES
CACHE=${PCP_TEST_FREEBSD_CACHE:-"$HOME/.cache/miniupnpd-pcp-test"}
MEMORY=${PCP_TEST_FREEBSD_MEMORY:-2048}
SSH_PORT=${PCP_TEST_FREEBSD_SSH_PORT:-2222}
KEEP_VM=${PCP_TEST_KEEP_VM:-0}
OUT_DIR=${PCP_TEST_OUT_DIR:-"$REPO_ROOT/.tmp/ci/out/freebsd/announce"}

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
KEY=
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$KEEP_VM" = 1 ]; then
		echo "Keeping VM (pid ${QEMU_PID:-none}); work dir $WORK; ssh -p $SSH_PORT -i $KEY freebsd@127.0.0.1" >&2
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

# A fixed key lives in the cache so a prepared image keeps accepting it.
KEY="$CACHE/id_ed25519"
if [ ! -f "$KEY" ]; then
	ssh-keygen -q -t ed25519 -N '' -f "$KEY"
fi
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
      - $(cat "$KEY.pub")
# The cloud image ships neither sudo nor doas; install doas as root at boot.
runcmd:
  - mkdir -p /usr/local/etc
  - echo 'IGNORE_OSVERSION = yes;' >> /usr/local/etc/pkg.conf
  - yes | env IGNORE_OSVERSION=yes ASSUME_ALWAYS_YES=yes pkg install -y doas
  - echo 'permit nopass freebsd' > /usr/local/etc/doas.conf
USER
mkseed "$WORK/seed.iso" "$WORK/seed"

ACCEL=tcg
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	ACCEL=kvm
else
	echo "No usable /dev/kvm; using slow software emulation." >&2
fi

RSH="ssh -p $SSH_PORT -i $KEY -o StrictHostKeyChecking=no \
 -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"
SSH="$RSH freebsd@127.0.0.1"

# boot_vm DISK: start QEMU on DISK and wait for SSH and sudo/doas (sets PRIV).
boot_vm() {
	qemu-system-x86_64 -machine accel=$ACCEL -cpu max -smp 2 -m "$MEMORY" \
		-display none -serial "file:$WORK/console.log" \
		-drive "file=$1,if=virtio" \
		-drive "file=$WORK/seed.iso,if=virtio,media=cdrom,readonly=on" \
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
		-device virtio-net-pci,netdev=n0 &
	QEMU_PID=$!
	echo "Waiting for the VM to accept SSH"
	attempt=0
	until $SSH true 2>/dev/null; do
		if ! kill -0 "$QEMU_PID" 2>/dev/null; then
			echo "QEMU exited early; console log:" >&2
			cat "$WORK/console.log" >&2
			exit 1
		fi
		attempt=$((attempt + 1))
		if [ "$attempt" -ge 120 ]; then
			echo "FreeBSD VM did not become reachable over SSH." >&2
			tail -40 "$WORK/console.log" >&2
			exit 1
		fi
		sleep 5
	done
	echo "Waiting for a privilege-escalation tool (sudo/doas) in the VM"
	PRIV=
	attempt=0
	while [ "$attempt" -lt 60 ]; do
		PRIV=$($SSH 'for t in sudo doas; do
			command -v $t >/dev/null || continue
			if [ $t = doas ] && [ ! -s /usr/local/etc/doas.conf ]; then continue; fi
			echo $t; break
		done' 2>/dev/null || true)
		[ -n "$PRIV" ] && break
		attempt=$((attempt + 1))
		sleep 5
	done
	if [ -z "$PRIV" ]; then
		echo "No sudo or doas became available in the VM." >&2
		tail -40 "$WORK/console.log" >&2
		exit 1
	fi
}

PREPARED="$CACHE/prepared-$VERSION.qcow2"
if [ ! -f "$PREPARED" ]; then
	echo "Preparing a cached FreeBSD $VERSION image (first run only)"
	qemu-img create -q -f qcow2 -F qcow2 -b "$CACHE/$IMAGE_NAME" "$WORK/prep.qcow2" 10G
	boot_vm "$WORK/prep.qcow2"
	$SSH "yes | $PRIV env IGNORE_OSVERSION=yes ASSUME_ALWAYS_YES=yes pkg install -y gmake pkgconf rsync" >/dev/null
	# libpfctl is a private base library: FreeBSD 15 ships neither its header
	# nor an installable library, so build a static copy from the matching
	# release branch (configure uses -I/usr/local/include -L/usr/local/lib).
	if [ "${VERSION%%.*}" -ge 15 ]; then
		$SSH "set -e
		    rel=\$(freebsd-version -u | sed 's/-.*//')
		    url=https://raw.githubusercontent.com/freebsd/freebsd-src/releng/\$rel/lib/libpfctl
		    cd /tmp && fetch -q \$url/libpfctl.h \$url/libpfctl.c
		    cc -O2 -I. -c libpfctl.c -o libpfctl.o
		    ar rcs libpfctl.a libpfctl.o
		    $PRIV mkdir -p /usr/local/include /usr/local/lib
		    $PRIV install -m 644 libpfctl.h /usr/local/include/
		    $PRIV install -m 644 libpfctl.a /usr/local/lib/"
	fi
	$SSH "$PRIV sync; $PRIV shutdown -p now" || true
	wait "$QEMU_PID" || true
	QEMU_PID=
	qemu-img convert -O qcow2 "$WORK/prep.qcow2" "$PREPARED.part"
	mv "$PREPARED.part" "$PREPARED"
	rm -f "$WORK/prep.qcow2"
fi

# Throwaway overlay so the cached image is never modified.
qemu-img create -q -f qcow2 -F qcow2 -b "$PREPARED" "$WORK/disk.qcow2" 10G
boot_vm "$WORK/disk.qcow2"

# Copy the tracked files plus uncommitted edits, without .git.  rsync when the
# VM has it (images prepared before rsync was added fall back to tar).
echo "Copying the checkout into the VM"
if $SSH 'command -v rsync >/dev/null'; then
	(cd "$REPO_ROOT" && git ls-files -co --exclude-standard -z) |
		rsync -rlpt --delete --from0 --files-from=- --ignore-missing-args \
		    -e "$RSH" --rsync-path="$PRIV rsync" \
		    "$REPO_ROOT/" freebsd@127.0.0.1:/root/miniupnp/
else
	(cd "$REPO_ROOT" && git ls-files -co --exclude-standard -z | tar --null -T - -cf -) |
		$SSH "$PRIV rm -rf /root/miniupnp && $PRIV mkdir -p /root/miniupnp && $PRIV tar -xf - -C /root/miniupnp"
fi

# Run the check, keeping its output; the exit code goes through a file because
# a pipeline through tee would hide it.
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
{
	rc=0
	$SSH "cd /root/miniupnp && $PRIV sh miniupnpd/tests/pcp_pmp/freebsd/check-announce.sh" 2>&1 || rc=$?
	echo $rc >"$OUT_DIR/exit-status"
} | tee "$OUT_DIR/check.log"
status=$(cat "$OUT_DIR/exit-status")
rm -f "$OUT_DIR/exit-status"

# Collect the in-VM logs (build, miniupnpd, tcpdump captures, configs).
$SSH "$PRIV tar -cf - -C /tmp announce-test" 2>/dev/null | tar -xf - -C "$OUT_DIR" || true
cp "$WORK/console.log" "$OUT_DIR/console.log" 2>/dev/null || true
echo "FreeBSD $VERSION, exit status $status" >"$OUT_DIR/summary.txt"
echo "Results saved to $OUT_DIR" >&2
exit "$status"
