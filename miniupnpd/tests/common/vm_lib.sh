# shellcheck shell=sh
# The QEMU VM steps the FreeBSD drivers share (freebsd_vm.sh for pcp_wire and daemon_options,
# pcp_e2e/run-freebsd.sh): the image, the cloud-init seed, the cached prepared image, the boot
# and the copy of the checkout. Sourced; the functions read and set the driver's variables:
#
#   CACHE     image cache dir (PCP_TEST_FREEBSD_CACHE, default ~/.cache/miniupnpd-pcp-test)
#   MEMORY    VM memory in MB (PCP_TEST_FREEBSD_MEMORY, default 2048)
#   WORK      the run's work dir (seed, console.log, disks)
#   SSH_PORT  host port forwarded to the VM's SSH
#   VM_USER   the cloud-init user (default freebsd)
#   VERSION   the FreeBSD release; empty: the newest with a cloud-init image
#   DETACH, MONITOR  optional: a command QEMU starts under, and its -monitor option
# set: IMAGE_NAME, KEY, RSH, SSH, ACCEL, QEMU_PID, PRIV, PREPARED.

CACHE=${CACHE:-${PCP_TEST_FREEBSD_CACHE:-"$HOME/.cache/miniupnpd-pcp-test"}}
MEMORY=${MEMORY:-${PCP_TEST_FREEBSD_MEMORY:-2048}}
VM_USER=${VM_USER:-freebsd}
VMLIB_BASE_URL=https://download.freebsd.org/releases/VM-IMAGES

# vmlib_tools TOOL...: these tools and one that writes the seed ISO (mkseed ISO DIR)
vmlib_tools() {
	for tool in "$@"; do
		command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required for the test VM." >&2; exit 2; }
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
}

# vmlib_lock / vmlib_unlock: the image lock. Runs in other slots share the cache: the download and
# the preparation of an image happen in one run while the others wait for it. Each function that
# writes to the cache takes it, so every driver locks the same way.
vmlib_lock() {
	mkdir -p "$CACHE"
	if command -v flock >/dev/null 2>&1; then exec 8>"$CACHE/image.lock"; flock 8; fi
}
vmlib_unlock() { exec 8>&-; }

vmlib_image_name() { echo "FreeBSD-$1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2"; }
vmlib_image_url() { echo "$VMLIB_BASE_URL/$1-RELEASE/amd64/Latest/$(vmlib_image_name "$1").xz"; }

# vmlib_freebsd_image: VERSION (the newest release with a cloud-init image when empty) and its
# image in CACHE, downloaded on the first use; sets IMAGE_NAME.
vmlib_freebsd_image() {
	if [ -z "$VERSION" ]; then
		for candidate in $(curl -fsS --retry 3 "$VMLIB_BASE_URL/" |
		    grep -o 'href="[0-9][0-9]*\.[0-9][0-9]*-RELEASE' | sed 's/href="//; s/-RELEASE//' |
		    sort -u -t. -k1,1nr -k2,2nr); do
			if curl -fsIL -o /dev/null "$(vmlib_image_url "$candidate")"; then
				VERSION=$candidate
				break
			fi
		done
		if [ -z "$VERSION" ]; then
			echo "Could not find a FreeBSD release with a cloud-init image at $VMLIB_BASE_URL." >&2
			echo "Set PCP_TEST_FREEBSD_VERSION (for example 14.5) to choose one." >&2
			exit 1
		fi
	fi
	echo "Using FreeBSD $VERSION"
	IMAGE_NAME=$(vmlib_image_name "$VERSION")
	vmlib_lock
	if [ ! -f "$CACHE/$IMAGE_NAME" ]; then
		echo "Downloading $(vmlib_image_url "$VERSION")"
		curl -fL --retry 3 -o "$CACHE/$IMAGE_NAME.xz.part" "$(vmlib_image_url "$VERSION")"
		xz -d -c "$CACHE/$IMAGE_NAME.xz.part" >"$CACHE/$IMAGE_NAME.part"
		rm -f "$CACHE/$IMAGE_NAME.xz.part"
		mv "$CACHE/$IMAGE_NAME.part" "$CACHE/$IMAGE_NAME"
	fi
	vmlib_unlock
}

# vmlib_ssh: the key (fixed, in CACHE, so a prepared image keeps accepting it), RSH and SSH
vmlib_ssh() {
	KEY="$CACHE/id_ed25519"
	vmlib_lock
	[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY"
	vmlib_unlock
	RSH="ssh -p $SSH_PORT -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"
	SSH="$RSH $VM_USER@127.0.0.1"
}

# vmlib_seed INSTANCE_ID: WORK/seed.iso, the cloud-init seed for VM_USER with the SSH key. The
# FreeBSD cloud image ships neither sudo nor doas: doas is installed at boot.
vmlib_seed() {
	vmlib_ssh
	rm -rf "$WORK/seed"
	mkdir "$WORK/seed"
	cat >"$WORK/seed/meta-data" <<META
instance-id: $1
local-hostname: pcp-bsd
META
	cat >"$WORK/seed/user-data" <<USER
#cloud-config
users:
  - name: $VM_USER
    groups: wheel
    shell: /bin/sh
    sudo: ALL=(ALL) NOPASSWD:ALL
    doas: permit nopass $VM_USER
    ssh_authorized_keys:
      - $(cat "$KEY.pub")
USER
	if [ "$VM_USER" = freebsd ]; then
		cat >>"$WORK/seed/user-data" <<USER
runcmd:
  - mkdir -p /usr/local/etc
  - echo 'IGNORE_OSVERSION = yes;' >> /usr/local/etc/pkg.conf
  - yes | env IGNORE_OSVERSION=yes ASSUME_ALWAYS_YES=yes pkg install -y doas
  - echo 'permit nopass freebsd' > /usr/local/etc/doas.conf
USER
	fi
	mkseed "$WORK/seed.iso" "$WORK/seed"
	ACCEL=tcg
	if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
		ACCEL=kvm
	else
		echo "No usable /dev/kvm; using slow software emulation." >&2
	fi
}

# vmlib_boot DISK [QEMU ARGUMENT...]: start QEMU on DISK (SSH on SSH_PORT), then wait for SSH
# and for sudo or doas (sets QEMU_PID and PRIV). QEMU gets none of the driver's locks (7: the slot,
# 8: the image cache, 9: a kept fixture): a kept VM outlives the driver, and would hold them.
vmlib_boot() {
	disk=$1
	shift
	# shellcheck disable=SC2086  # DETACH and MONITOR are empty or words without blanks
	${DETACH:-} qemu-system-x86_64 ${MONITOR:-} -machine accel=$ACCEL -cpu max -smp 2 -m "$MEMORY" \
		-display none -serial "file:$WORK/console.log" \
		-drive "file=$disk,if=virtio" \
		-drive "file=$WORK/seed.iso,if=virtio,media=cdrom,readonly=on" \
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
		-device virtio-net-pci,netdev=n0 "$@" </dev/null >"$WORK/qemu.log" 2>&1 7>&- 8>&- 9>&- &
	QEMU_PID=$!
	echo "Waiting for the VM to accept SSH"
	attempt=0
	until $SSH true 2>/dev/null; do
		if ! kill -0 "$QEMU_PID" 2>/dev/null; then
			echo "QEMU exited early; console log:" >&2
			cat "$WORK/qemu.log" "$WORK/console.log" >&2
			exit 1
		fi
		attempt=$((attempt + 1))
		if [ "$attempt" -ge 120 ]; then
			echo "The VM did not become reachable over SSH." >&2
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

# vmlib_prepared PREPARE_SCRIPT NAME: PREPARED, the image IMAGE_NAME with PREPARE_SCRIPT run in it,
# cached as NAME-<hash of the script>.qcow2 and made on the first use (under the image lock).
vmlib_prepared() {
	prepare_id=$( (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -c1-8)
	PREPARED="$CACHE/$2-$prepare_id.qcow2"
	vmlib_lock
	if [ ! -f "$PREPARED" ]; then
		echo "Preparing the cached image $(basename "$PREPARED") (first run only)"
		qemu-img create -q -f qcow2 -F qcow2 -b "$CACHE/$IMAGE_NAME" "$WORK/prep.qcow2" 10G
		vmlib_boot "$WORK/prep.qcow2"
		$SSH "$PRIV env PCP_TEST_PYTHON=1 sh -c \"\$(cat)\"" <"$1"
		$SSH "$PRIV sync; if [ \$(uname) = Linux ]; then $PRIV poweroff; else $PRIV shutdown -p now; fi" || true
		wait "$QEMU_PID" || true
		QEMU_PID=
		qemu-img convert -O qcow2 "$WORK/prep.qcow2" "$PREPARED.part"
		mv "$PREPARED.part" "$PREPARED"
		rm -f "$WORK/prep.qcow2"
	fi
	vmlib_unlock
}

# vmlib_copy ROOT LIST_FUNCTION RSYNC_FLAGS: copy the files LIST_FUNCTION prints (NUL-separated,
# relative to ROOT) to /root/miniupnp in the VM, without .git. rsync when the VM has it (deleting
# what is gone), else tar.
vmlib_copy() {
	echo "Copying the checkout into the VM"
	if $SSH 'command -v rsync >/dev/null'; then
		"$2" | rsync "$3" --delete --from0 --files-from=- --ignore-missing-args \
			-e "$RSH" --rsync-path="$PRIV rsync" "$1/" "$VM_USER@127.0.0.1:/root/miniupnp/"
	else
		"$2" | (cd "$1" && tar --null -T - -cf -) |
			$SSH "$PRIV rm -rf /root/miniupnp && $PRIV mkdir -p /root/miniupnp && $PRIV tar -xf - -C /root/miniupnp"
	fi
}
