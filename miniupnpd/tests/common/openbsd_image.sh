# An installed OpenBSD disk image for the QEMU fixtures. OpenBSD publishes no cloud image, so the
# image is made once with the official installer, unattended, and kept in the cache.
#
# The VM boots by PXE from QEMU's own TFTP server (pxeboot, then bsd.rd), with the console on the
# serial port. The installer asks for a response file; a small script on the serial console answers
# with the URL of install.conf on the host, which a local HTTP server serves (QEMU's user network
# sends 10.0.2.2 to the host's 127.0.0.1). pxeboot and bsd.rd are checked against the SHA256 file of
# the release, fetched over HTTPS; the sets come from cdn.openbsd.org and the installer checks them
# with signify. A second boot as root then writes /etc/doas.conf.
#
# Source this file. Needs qemu-system-x86_64, qemu-img, curl, python3, sha256sum.

# openbsd_base_image VERSION CACHE KEY USER: make CACHE/openbsd-VERSION-base.qcow2 if it is missing:
# OpenBSD VERSION with the base, comp and man sets, sshd, root and USER login by the public key
# KEY.pub, the console on com0 and "permit nopass USER" in doas.conf.
openbsd_base_image() {
	obi_version=$1; obi_cache=$2; obi_key=$3; obi_user=$4
	obi_image=$obi_cache/openbsd-$obi_version-base.qcow2
	[ -f "$obi_image" ] && return 0
	obi_url=https://cdn.openbsd.org/pub/OpenBSD/$obi_version/amd64
	obi_work=$(mktemp -d)
	mkdir -p "$obi_work/tftp/etc" "$obi_work/http"

	echo "Building an OpenBSD $obi_version image (first run only, about five minutes)"
	for f in SHA256 pxeboot bsd.rd; do
		curl -fsSL --retry 3 -o "$obi_work/tftp/$f" "$obi_url/$f" || { rm -rf "$obi_work"; return 1; }
	done
	(cd "$obi_work/tftp" && grep -E '\((pxeboot|bsd\.rd)\)' SHA256 | sed 's/^SHA256 (\(.*\)) = \(.*\)/\2  \1/' |
		sha256sum -c --quiet) || { echo "OpenBSD boot files fail their SHA256" >&2; rm -rf "$obi_work"; return 1; }
	cp "$obi_work/tftp/bsd.rd" "$obi_work/tftp/bsd"
	printf 'stty com0 115200\nset tty com0\nboot tftp:/bsd.rd\n' >"$obi_work/tftp/etc/boot.conf"

	obi_pub=$(cat "$obi_key.pub")
	cat >"$obi_work/http/install.conf" <<CONF
System hostname = pcp-obsd
Network interface to configure = vio0
IPv4 address for vio0 = autoconf
IPv6 address for vio0 = none
Which network interface do you wish to configure = done
Password for root account = pcp-test-root
Public ssh key for root account = $obi_pub
Start sshd(8) by default = yes
Do you expect to run the X Window System = no
Change the default console to com0 = yes
Which speed should com0 use = 115200
Setup a user = $obi_user
Full name for user $obi_user = $obi_user
Password for user $obi_user = pcp-test-user
Public ssh key for user $obi_user = $obi_pub
Allow root ssh login = prohibit-password
What timezone are you in = UTC
Which disk is the root disk = sd0
Encrypt the root disk with a (p)assphrase or (k)eydisk = no
Use (W)hole disk MBR, whole disk (G)PT or (E)dit = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a
Location of sets = http
HTTP proxy URL = none
HTTP Server = cdn.openbsd.org
Server directory = pub/OpenBSD/$obi_version/amd64
Set name(s) = -x* -game* done
Exit to (S)hell, (H)alt or (R)eboot = reboot
CONF

	obi_port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
	python3 -m http.server --bind 127.0.0.1 --directory "$obi_work/http" "$obi_port" \
		>"$obi_work/http.log" 2>&1 &
	obi_http=$!
	obi_accel=tcg
	[ -r /dev/kvm ] && [ -w /dev/kvm ] && obi_accel=kvm
	# 10G: the size vm_lib.sh gives the overlays on it
	qemu-img create -q -f qcow2 "$obi_work/disk.qcow2" 10G
	# -no-reboot: QEMU exits when the installer reboots at the end
	qemu-system-x86_64 -machine accel=$obi_accel -cpu max -smp 2 -m 1024 -display none -no-reboot \
		-chardev "socket,id=con,path=$obi_work/serial.sock,server=on,wait=off,logfile=$obi_work/install.log" \
		-serial chardev:con -boot n \
		-drive "file=$obi_work/disk.qcow2,if=virtio" \
		-netdev "user,id=n0,tftp=$obi_work/tftp,bootfile=pxeboot" \
		-device virtio-net-pci,netdev=n0 </dev/null >"$obi_work/qemu.log" 2>&1 &
	obi_qemu=$!
	obi_ok=0
	python3 - "$obi_work/serial.sock" "http://10.0.2.2:$obi_port/install.conf" <<'PY' && obi_ok=1
import socket, sys, time
# Answer the installer on the serial console until the install is done (QEMU then exits).
path, url = sys.argv[1], sys.argv[2]
for _ in range(100):
    try:
        sock = socket.socket(socket.AF_UNIX); sock.connect(path); break
    except OSError:
        time.sleep(0.2)
sock.settimeout(5)
seen, done, deadline = b"", {}, time.time() + 3600
prompts = [(b"(I)nstall, (U)pgrade, (A)utoinstall or (S)hell?", b"a\n"),
           (b"Response file location?", url.encode() + b"\n")]
while time.time() < deadline:
    try:
        chunk = sock.recv(4096)
    except socket.timeout:
        continue
    if not chunk:
        sys.exit(0 if b"CONGRATULATIONS" in seen else 1)
    seen += chunk
    # answer each appearance of a prompt once: the installer asks again after a failed fetch
    for prompt, answer in prompts:
        if seen.count(prompt) > done.get(prompt, 0):
            done[prompt] = seen.count(prompt)
            sock.sendall(answer)
sys.exit(1)
PY
	wait "$obi_qemu" 2>/dev/null || true
	kill "$obi_http" 2>/dev/null || true
	if [ "$obi_ok" != 1 ] || ! grep -q CONGRATULATIONS "$obi_work/install.log"; then
		echo "The OpenBSD install did not finish; console log:" >&2
		tail -40 "$obi_work/install.log" >&2
		cp "$obi_work/install.log" "$obi_cache/openbsd-$obi_version-install.log" 2>/dev/null || true
		rm -rf "$obi_work"
		return 1
	fi

	# First boot from the disk, as root: doas for the user. sshd makes its host keys on this boot.
	obi_ssh_port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
	qemu-system-x86_64 -machine accel=$obi_accel -cpu max -smp 2 -m 1024 -display none \
		-serial "file:$obi_work/boot.log" \
		-drive "file=$obi_work/disk.qcow2,if=virtio" \
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$obi_ssh_port-:22" \
		-device virtio-net-pci,netdev=n0 </dev/null >>"$obi_work/qemu.log" 2>&1 &
	obi_qemu=$!
	obi_ssh="ssh -p $obi_ssh_port -i $obi_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 root@127.0.0.1"
	obi_try=0
	until $obi_ssh true 2>/dev/null; do
		obi_try=$((obi_try + 1))
		if [ "$obi_try" -ge 120 ] || ! kill -0 "$obi_qemu" 2>/dev/null; then
			echo "The installed OpenBSD VM did not answer over SSH; console log:" >&2
			tail -40 "$obi_work/boot.log" >&2
			kill "$obi_qemu" 2>/dev/null || true
			rm -rf "$obi_work"
			return 1
		fi
		sleep 5
	done
	$obi_ssh "echo 'permit nopass $obi_user' > /etc/doas.conf && chmod 600 /etc/doas.conf && sync && halt -p" || true
	obi_try=0
	while kill -0 "$obi_qemu" 2>/dev/null && [ "$obi_try" -lt 60 ]; do obi_try=$((obi_try + 1)); sleep 2; done
	kill "$obi_qemu" 2>/dev/null || true
	wait "$obi_qemu" 2>/dev/null || true
	qemu-img convert -O qcow2 "$obi_work/disk.qcow2" "$obi_image.part"
	mv "$obi_image.part" "$obi_image"
	rm -rf "$obi_work"
}
