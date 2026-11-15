# Daemon options Test Status

One column per platform; a run updates only its own platform's column (raw results: `/tmp/pcp-results/status-data.json`).

## Platforms

- **linux**: **88 PASS**, **1 XFAIL**, **3 FAIL**, **0 SKIP** (updated 2026-11-12T08:51:05+00:00; ipv4: daemon `dev/daemon-options-tests`, router `Linux nftables (Docker)`; ipv6: daemon `dev/daemon-options-tests`, router `Linux nftables (Docker)`)
- **freebsd**: **82 PASS**, **1 XFAIL**, **8 FAIL**, **0 SKIP** (updated 2026-11-12T09:44:33+00:00; ipv4: daemon `dev/daemon-options-tests`, router `FreeBSD pf`; ipv6: daemon `dev/daemon-options-tests`, router `FreeBSD pf`)

## Results by section

### Protocol switches

enable_pcp_pmp (and its synonym enable_natpmp) and enable_upnp turn whole protocols on or off. A protocol that is off gives no reply: no PCP / NAT-PMP response on UDP 5351, no listener on the UPnP HTTP port. The protocols that stay on still answer.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| all-on-natpmp-answers | natpmp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from lan] With every protocol on, a NAT-PMP public address request is answered. |
| all-on-pcp-answers | pcp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from lan] With every protocol on, a PCP ANNOUNCE is answered. |
| all-on-pcp-answers | pcp | ipv6 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from lan] With every protocol on, a PCP ANNOUNCE is answered. |
| all-on-upnp-answers | upnp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from lan] With every protocol on, a UPnP AddPortMapping succeeds (the mapping is deleted again). |
| pcp-pmp-off-natpmp-silent | natpmp | ipv4 | PASS | PASS | [enable_pcp_pmp=no; enable_upnp=yes; http_port=5000; from lan] enable_pcp_pmp=no turns NAT-PMP off; a public address request gets no reply. |
| pcp-pmp-off-pcp-silent | pcp | ipv4 | PASS | PASS | [enable_pcp_pmp=no; enable_upnp=yes; http_port=5000; from lan] enable_pcp_pmp=no turns PCP off; an ANNOUNCE gets no reply. |
| pcp-pmp-off-pcp-silent-ipv6 | pcp | ipv6 | PASS | PASS | [enable_pcp_pmp=no; enable_upnp=yes; http_port=5000; from lan] enable_pcp_pmp=no turns PCP off; an ANNOUNCE gets no reply. |
| pcp-pmp-off-upnp-answers | upnp | ipv4 | PASS | PASS | [enable_pcp_pmp=no; enable_upnp=yes; http_port=5000; from lan] With PCP and NAT-PMP off, UPnP still answers. |
| natpmp-off-natpmp-silent | natpmp | ipv4 | PASS | PASS | [enable_natpmp=no; enable_upnp=yes; http_port=5000; from lan] enable_natpmp=no turns NAT-PMP off; a public address request gets no reply. |
| natpmp-off-pcp-silent | pcp | ipv4 | PASS | PASS | [enable_natpmp=no; enable_upnp=yes; http_port=5000; from lan] enable_natpmp=no turns PCP off too: it is the same option as enable_pcp_pmp (options.c). |
| natpmp-off-pcp-silent-ipv6 | pcp | ipv6 | PASS | PASS | [enable_natpmp=no; enable_upnp=yes; http_port=5000; from lan] enable_natpmp=no turns PCP off too: it is the same option as enable_pcp_pmp (options.c). |
| natpmp-off-upnp-answers | upnp | ipv4 | PASS | PASS | [enable_natpmp=no; enable_upnp=yes; http_port=5000; from lan] With enable_natpmp=no, UPnP still answers. |
| upnp-off-upnp-no-listener | upnp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=no; http_port=5000; from lan] enable_upnp=no opens no HTTP listener, also with http_port=5000. |
| upnp-off-natpmp-answers | natpmp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=no; http_port=5000; from lan] With UPnP off, NAT-PMP still answers. |
| upnp-off-pcp-answers | pcp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=no; http_port=5000; from lan] With UPnP off, PCP still answers. |
| upnp-off-pcp-answers | pcp | ipv6 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=no; http_port=5000; from lan] With UPnP off, PCP still answers. |

### WAN side

Requests from a host on the router's WAN link to the router's WAN address, with every protocol on: the daemon serves its LAN (listening_ip) only, so none of them gets a reply.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| wan-natpmp-silent | natpmp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from wan] A NAT-PMP public address request to router-wan:5351 gets no reply. |
| wan-pcp-announce-silent | pcp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from wan] A PCP ANNOUNCE to router-wan:5351 gets no reply. |
| wan-pcp-announce-silent | pcp | ipv6 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from wan] A PCP ANNOUNCE to router-wan:5351 gets no reply. |
| wan-pcp-map-silent | pcp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from wan] A PCP MAP to router-wan:5351 gets no reply (and makes no mapping). |
| wan-pcp-map-silent | pcp | ipv6 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from wan] A PCP MAP to router-wan:5351 gets no reply (and makes no mapping). |
| wan-upnp-no-reply | upnp | ipv4 | PASS | PASS | [enable_pcp_pmp=yes; enable_upnp=yes; http_port=5000; from wan] A UPnP AddPortMapping to router-wan:5000 gets no HTTP response. |

### Lifetime options

min_lifetime and max_lifetime bound the lifetime the daemon grants a PCP mapping. The same kind of request runs under different values. pcp_min_lifetime_override is not in this branch's options.c and has no case here.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| max-lifetime-300-caps-pcp | pcp | ipv4 | PASS | PASS | [max_lifetime=300; from lan] max_lifetime=300 grants 300 s for a request of 3600 s. |
| max-lifetime-900-caps-pcp | pcp | ipv4 | PASS | PASS | [max_lifetime=900; from lan] max_lifetime=900 grants 900 s for the same request of 3600 s. |
| max-lifetime-clamped-to-86400 | pcp | ipv4 | PASS | PASS | [max_lifetime=100000; from lan] A max_lifetime above 86400 is lowered to 86400 at startup. |
| min-lifetime-300-raises-pcp | pcp | ipv4 | PASS | PASS | [min_lifetime=300; from lan] min_lifetime=300 grants 300 s for a request of 130 s. |
| min-lifetime-clamped-to-120 | pcp | ipv4 | PASS | PASS | [min_lifetime=2; from lan] A min_lifetime below 120 is raised to 120 at startup. |
| max-lifetime-300-natpmp-not-capped | natpmp | ipv4 | PASS | PASS | [max_lifetime=300; from lan] max_lifetime is a PCP option (miniupnpd.conf); a NAT-PMP mapping keeps the lifetime it asked for. |

### Secure mode and third-party mappings

secure_mode limits UPnP clients to mappings for their own address. pcp_allow_thirdparty lets a PCP client map for another address with the THIRD_PARTY option.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| secure-on-upnp-other-client-refused | upnp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; secure_mode=yes; from lan] secure_mode=yes refuses a UPnP mapping for another LAN address. |
| secure-off-upnp-other-client-allowed | upnp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; secure_mode=no; from lan] secure_mode=no accepts a UPnP mapping for another LAN address. |
| thirdparty-off-pcp-refused | daemon | ipv4 | PASS | PASS | [pcp_allow_thirdparty=no; from lan] With pcp_allow_thirdparty=no, THIRD_PARTY for a LAN neighbour is refused. |
| thirdparty-on-secure-on-pcp | daemon | ipv4 | PASS | PASS | [pcp_allow_thirdparty=yes; secure_mode=yes; from lan] pcp_allow_thirdparty=yes maps for a LAN neighbour; secure_mode covers UPnP only (pcpserver.c does not read it). |
| thirdparty-on-secure-off-pcp | daemon | ipv4 | PASS | PASS | [pcp_allow_thirdparty=yes; secure_mode=no; from lan] The same THIRD_PARTY request with secure_mode=no. |
| thirdparty-on-wan-pcp-silent | pcp | ipv4 | PASS | PASS | [pcp_allow_thirdparty=yes; secure_mode=yes; from wan] pcp_allow_thirdparty=yes skips the LAN check of the sender; a PCP MAP from the WAN side still gets no reply. |

### Permission rules

allow and deny lines decide which mappings a client gets, for all three protocols: the first line that matches the external port, the client address and the internal port decides, and without a match the mapping is accepted. miniupnpd has no quota option and no static mappings, so the plan's limits and static scenarios have nothing to vary.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| perm-pcp-inside | pcp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 0.0.0.0/0 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A PCP MAP inside the allowed ports succeeds. |
| perm-pcp-outside | pcp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 0.0.0.0/0 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A PCP MAP for an internal port no rule allows is refused. |
| perm-natpmp-inside | natpmp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 0.0.0.0/0 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A NAT-PMP mapping inside the allowed ports succeeds. |
| perm-natpmp-outside | natpmp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 0.0.0.0/0 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A NAT-PMP mapping for an internal port no rule allows is refused. |
| perm-upnp-inside | upnp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 0.0.0.0/0 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A UPnP mapping inside the allowed ports succeeds. |
| perm-upnp-outside | upnp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 0.0.0.0/0 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A UPnP mapping outside the allowed ports is refused. |
| perm-pcp-moves-external-port | pcp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 0.0.0.0/0 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A PCP MAP that suggests a denied external port gets an allowed one. |
| perm-pcp-ipv6-outside-refused | pcp | ipv6 | FAIL | FAIL | linux: unexpected result code 0; freebsd: unexpected result code 0 |
| perm-address-pcp-refused | pcp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 10.0.0.0/8 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A rule for another subnet does not allow this client (PCP). |
| perm-address-natpmp-refused | natpmp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 10.0.0.0/8 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A rule for another subnet does not allow this client (NAT-PMP). |
| perm-address-upnp-refused | upnp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; allow 46000-46100 10.0.0.0/8 46000-46100; deny 0-65535 0.0.0.0/0 0-65535; from lan] A rule for another subnet does not allow this client (UPnP). |
| perm-deny-only-denied-port | upnp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; deny 46200-46300 0.0.0.0/0 0-65535; from lan] A deny line refuses its ports. |
| perm-deny-only-other-port-accepted | upnp | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; deny 46200-46300 0.0.0.0/0 0-65535; from lan] Without a matching line a mapping is accepted. |

### Daemon start

Configurations the daemon must refuse: it exits instead of listening.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| both-protocols-off-exits | daemon | ipv4 | PASS | PASS | [enable_upnp=no; enable_pcp_pmp=no; from lan] With UPnP and PCP/NAT-PMP off the daemon exits at start. |
| min-above-max-lifetime-exits | daemon | ipv4 | PASS | PASS | [min_lifetime=600; max_lifetime=300; from lan] min_lifetime at or above max_lifetime is refused at start. |
| ext-ip-with-stun-exits | daemon | ipv4 | PASS | PASS | [ext_ip=203.0.113.9; ext_perform_stun=yes; ext_stun_host=@WAN4@.5; from lan] ext_ip and ext_perform_stun are refused together. |
| stun-without-host-exits | daemon | ipv4 | PASS | PASS | [ext_perform_stun=yes; from lan] ext_perform_stun needs ext_stun_host. |

### External address

The address the daemon reports and how it finds it: ext_ip, STUN, ext_ifname, ext_ifname6 and the check of a private address.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| ext-ip-reported | daemon | ipv4 | PASS | PASS | [ext_ip=203.0.113.9; from lan] ext_ip is the address NAT-PMP reports. |
| ext-ifname-address-reported | daemon | ipv4 | PASS | PASS | [ext_ifname=eth0; from lan] ext_ifname selects the interface whose address is reported. |
| private-address-allowed | daemon | ipv4 | PASS | PASS | [ext_allow_private_ipv4=yes; from lan] ext_allow_private_ipv4=yes forwards on a reserved WAN address. |
| private-address-refused | daemon | ipv4 | PASS | PASS | [ext_allow_private_ipv4=no; from lan] ext_allow_private_ipv4=no refuses mappings once the WAN address is a reserved one. |
| stun-address-default-port | daemon | ipv4 | PASS | FAIL | freebsd: the daemon did not start |
| stun-address-other-port | daemon | ipv4 | PASS | FAIL | freebsd: the daemon did not start |
| stun-filtered-refuses-mappings | daemon | ipv4 | PASS | FAIL | freebsd: the daemon did not start |
| ext-ifname6-used | daemon | ipv6 | PASS | PASS | [ext_ifname6=eth0; from lan] ext_ifname6 is accepted and an IPv6 mapping is made through it. |

### Addresses the daemon listens on

listening_ip, ipv6_listening_ip and ipv6_disable.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| listening-ip-by-address | daemon | ipv4 | PASS | PASS | [listening_ip=@LAN4@.1/24; ipv6_disable=yes; from lan] listening_ip takes an address and mask instead of an interface. |
| ipv6-listening-ip | daemon | ipv6 | PASS | PASS | [ipv6_listening_ip=@LAN6@1; from lan] ipv6_listening_ip binds the IPv6 PCP socket. |
| ipv6-disable-silent | pcp | ipv6 | PASS | PASS | [ipv6_disable=yes; from lan] ipv6_disable=yes opens no IPv6 PCP socket. |
| ipv6-disable-upnp-starts | daemon | ipv4 | PASS | FAIL | freebsd: the daemon did not start |

### UPnP description

The strings of the device description, and the numbers of the WAN common interface.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| description-strings | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; friendly_name=OptFriendly; manufacturer_name=OptMaker; manufacturer_url=http://maker.example/; model_name=OptModel; model_description=OptDescription; model_url=http://model.example/; model_number=OptNumber; serial=OptSerial; uuid=12345678-1234-1234-1234-123456789abc; presentation_url=http://router.example/ui; from lan] Each description option appears in rootDesc.xml. |
| description-default | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; from lan] Without the options none of the strings appear, and an IGDv2 build describes itself as v2. |
| force-igd-desc-v1 | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; force_igd_desc_v1=yes; from lan] force_igd_desc_v1 describes the device as IGD v1. |
| bitrates | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; bitrate_up=1000000; bitrate_down=2000000; from lan] bitrate_up and bitrate_down are the reported link speeds. |
| https-port | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; https_port=5443; from lan] https_port serves the description over TLS. |
| minissdpd-socket | daemon | ipv4 | PASS | — | [enable_upnp=yes; http_port=5000; minissdpdsocket=/tmp/minissdpd.sock; from lan] The daemon submits its services to the minissdpd socket. |
| packet-log-accepted | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; packet_log=yes; from lan] packet_log=yes is accepted; the daemon sets the flag and never reads it. |

### Timers

notify_interval, system_uptime, and the clean_ruleset pair.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| notify-interval-short | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; notify_interval=2; from lan] notify_interval=2 repeats the SSDP NOTIFYs. |
| notify-default-quiet | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; from lan] The default interval of 900 s sends none after the startup round. |
| clean-ruleset-keeps-natpmp-mapping | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; clean_ruleset_interval=3; clean_ruleset_threshold=0; from lan] clean_ruleset removes unused UPnP rules; a NAT-PMP mapping has a lifetime and stays until it expires. |
| ssdp-off-with-upnp-off | daemon | ipv4 | PASS | PASS | [enable_upnp=no; from lan] With UPnP off there are no NOTIFYs. |
| system-uptime-off | daemon | ipv4 | PASS | PASS | [system_uptime=no; from lan] The NAT-PMP epoch counts from the start of the daemon. |
| system-uptime-on | daemon | ipv4 | PASS | — | [system_uptime=yes; from lan] system_uptime=yes makes the epoch the uptime of the system. |
| clean-ruleset-removes-idle | daemon | ipv4 | FAIL | PASS | linux: step 8: mapping 46321 is not absent: {'_element': 'GetSpecificPortMappingEntryResponse', 'NewInternalPort': '46321', 'NewInternalClient': '172.28.77.2', 'NewEnabled': '1', 'NewPortMappingDescription': 'pcp-e2e upnp', 'NewLeaseDuration': '3591'} |
| clean-ruleset-threshold-keeps | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; clean_ruleset_interval=2; clean_ruleset_threshold=10; from lan] Below clean_ruleset_threshold rules, nothing is removed. |
| clean-ruleset-off-keeps | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; clean_ruleset_interval=0; from lan] clean_ruleset_interval=0 removes nothing. |

### Firewall rules lost

A reload of the firewall removes the rules and the daemon is not told. A renewal must see that and add the rules again, or the client is told of a mapping which passes nothing.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| firewall-lost-upnp-renew | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; lease_file=/var/lib/miniupnpd/firewall.leases; from lan] A UPnP renewal adds rules which were lost. |
| firewall-lost-pcp-renew | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; lease_file=/var/lib/miniupnpd/firewall.leases; from lan] A PCP renewal adds rules which were lost. |
| firewall-lost-natpmp-renew | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; lease_file=/var/lib/miniupnpd/firewall.leases; from lan] A NAT-PMP renewal adds rules which were lost. |
| firewall-lost-after-restart | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; lease_file=/var/lib/miniupnpd/firewall.leases; from lan] A rule restored at startup is checked like one added by a request. |
| firewall-lost-pinhole-update | daemon | ipv6 | FAIL | FAIL | linux: step 3: UpdatePinhole: HTTP 500, SoapFault(code=704, description='NoSuchEntry'); freebsd: step 3: UpdatePinhole: HTTP 500, SoapFault(code=704, description='NoSuchEntry') |
| firewall-lost-no-request | daemon | ipv4 | XFAIL | XFAIL | linux: step 5: ruleset: '46346' not found in: 'iniupnpd {\n\t}\n\n\tchain prerouting {\n\t\tcomment "created by miniupnpd init script"\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tjump prerouting_miniupnpd\n\t}\n\n\tchain postrouting {\n\t\tcomment "created by miniupnpd init script"\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\tjump postrouting_miniupnpd\n\t}\n\n\tchain prerouting_miniupnpd {\n\t}\n\n\tchain postrouting_miniupnpd {\n\t}\n}\n'; expected: miniupnpd re-adds a lost rule only when a client renews or updates the mapping; freebsd: step 5: ruleset: '46346' not found in: ''; expected: miniupnpd re-adds a lost rule only when a client renews or updates the mapping |

### Lease files

A mapping survives a restart through the lease file only. The restart makes a new network namespace, so the rules do not survive by themselves.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| lease-file-restores | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; from lan] With lease_file a UPnP mapping is back after a restart. |
| lease-file-off-loses | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; lease_file=@OFF@; from lan] Without lease_file the mapping is gone after a restart. |
| lease-file-path | daemon | ipv4 | PASS | PASS | [enable_upnp=yes; http_port=5000; lease_file=/var/lib/miniupnpd/other.leases; from lan] lease_file sets the path of the file. |
| lease-file6-path | daemon | ipv6 | PASS | — | [lease_file6=/var/lib/miniupnpd/pinholes.leases; from lan] lease_file6 sets the path of the IPv6 lease file, where a PCP IPv6 mapping is written too. |

### Firewall names (nftables)

The table and chain options, created by nft_init.sh -f and used by the daemon.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| nft-names | daemon | ipv4 | PASS | — | [enable_upnp=yes; http_port=5000; upnp_table_name=opttable; upnp_nat_table_name=optnat; upnp_forward_chain=optforward; upnp_nat_chain=optprerouting; upnp_nat_postrouting_chain=optpostrouting; from lan] The mapping lands in the named tables and chains. |
| nft-family-split | daemon | ipv4 | PASS | — | [enable_upnp=yes; http_port=5000; upnp_nftables_family_split=yes; from lan] With the family split the IPv4 rules are in an ip table. |

### Third party traffic

Traffic from the WAN reaches a second LAN host through a mapping another client made.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| thirdparty-traffic-reaches-neighbour | daemon | ipv4 | PASS | PASS | [pcp_allow_thirdparty=yes; from lan] A THIRD_PARTY mapping forwards WAN traffic to the other LAN host. |

### Firewall names (pf)

The options of the pf backend, on FreeBSD only: the rules a mapping makes.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| pf-anchor | daemon | ipv4 | — | PASS | [anchor=optanchor; from lan] The rules of a mapping land in the named anchor. |
| pf-tag | daemon | ipv4 | — | PASS | [tag=opttag; from lan] tag sets the tag of the filter rule. |
| pf-queue | daemon | ipv4 | — | FAIL | freebsd: step 2: ruleset: 'queue optqueue' not found in: 'nat quick on bridge1 inet proto udp from 172.28.41.2 port = 46351 to any keep state label "NAT-PMP 46351 UDP" rtable 0 -> 198.51.100.1 port 46351\nrdr pass quick on bridge1 inet proto udp from any to any port = 46351 keep state label "NAT-PMP 46351 UDP" rtable 0 -> 172.28.41.2 port 46351\n' |
| pf-quickrules | daemon | ipv4 | — | FAIL | freebsd: the daemon did not start |
