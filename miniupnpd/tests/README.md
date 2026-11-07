# miniupnpd tests

Integration tests of the PCP and NAT-PMP support. Run them from the repository root.

Each suite has a `README.md` with its options and a `status.md` with its latest results. Runs need
Docker (`run-docker.sh` also needs Compose); the FreeBSD drivers also need QEMU. The self-tests need only python3 with PyYAML.

## IP setup

Runs side by side use *slots*: sets of predefined addresses, one per run, because Docker bridges
share the host's routing table and refuse overlapping subnets. Every suite and platform shares one
pool: `reserve_slot` in `common/e2e_lib.sh` gives a run the first free slot N of 1-128 and holds it
with a lock file in `/tmp/pcp-e2e-slots/` until the run ends.

| LAN | WAN |
|---|---|
| `172.28.N.0/24`, `2001:db8:1:N::/64` | `6.18.N.0/24`, `2001:db8:9000:N::/64` |

Hosts keep their last octet in every slot: router `.1`, LAN client `.2`, Docker gateway `.254`. The
WAN is public space on purpose, so the daemon sees a normal WAN address; the host cannot reach those
addresses during a run. A suite's `*_SLOT` setting picks a slot by hand.
