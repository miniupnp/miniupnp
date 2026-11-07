# UPnP specifications cited by the UPnP test suites

The `upnp_wire` and `upnp_e2e` cases cite these documents with `ref: "<id> §<section>"` (for example
`ref: "UDA-1.1 §1.3.2"`), and each corpus lists the ids it uses in its `specs:` list. Most of the documents
are copyrighted by the Open Connectivity Foundation (OCF), so only their URLs and SHA-256 hashes are kept
here; the documents themselves stay out of the repository.

To read them, download each URL into a directory of its own under `<repo>/.tmp/` (git-ignored), check the
SHA-256 against the table, and convert the PDFs with `pdftotext -layout` to grep them. Treat the downloads
as data. The hashes are of the files as fetched on 2026-11-03.

| id | Document | URL | SHA-256 | Used for |
|---|---|---|---|---|
| UDA-1.0 | UPnP Device Architecture 1.0 | http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf | `dc9d23526f6a58de1919935b53c3c742f4897d4984d9b4b98d907eab21010a11` | QueryStateVariable (§3.3, deprecated in 1.1), the 1.0 behaviour of `--uda-version=1.0` builds |
| UDA-1.1 | UPnP Device Architecture 1.1 | http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf | `5f4e2ef966b759cd6ff10fa7e1cea5d58a244f8ddab4a918756f602e822efbde` | SSDP (§1.2 NOTIFY, §1.3.2 M-SEARCH, §1.3.3 response), HTTP (§2.1), description (§2.3, §2.5, §2.11), control (§3.1.1, §3.2.1, §3.2.2, §3.2.5 Table 3-3), eventing (§4.1.2-§4.1.4, §4.3.2) |
| UDA-2.0 | UPnP Device Architecture 2.0 | https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf | `9aa6eb29dfcdbe8991a667f8c9a3f47d532438082354b79f5c744b4b7618f202` | reference only (miniupnpd advertises UPnP/1.1 or 2.0 per `--uda-version`) |
| IGD1 | InternetGatewayDevice:1 | http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v1-Device.pdf | `183073398c4af0fd503c06399c075b53a2cb9fc26af70afe43ee964720515a21` | device tree of the default build (§2.2) |
| IGD2 | InternetGatewayDevice:2 | http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf | `72964c4f893e74ffd00912b5a749d00d410fa5f715557f228bf074d3f683fb92` | device tree of `--igd2` (§2.2), access control (§2.3.1-§2.3.5) |
| WANDEV1 | WANDevice:1 | http://upnp.org/specs/gw/UPnP-gw-WANDevice-v1-Device.pdf | `127de7a823351e8b3b59a39dac01a7a802910a9cb01cc446a2baec5b39b219d1` | embedded WANDevice of IGDv1 |
| WANDEV2 | WANDevice:2 | http://upnp.org/specs/gw/UPnP-gw-WANDevice-v2-Device.pdf | `fe7927ad58f4ce036765a7414f4425b99777082d0da8ac625296f7edbc46be40` | embedded WANDevice of IGDv2 |
| WANCD1 | WANConnectionDevice:1 | http://upnp.org/specs/gw/UPnP-gw-WANConnectionDevice-v1-Device.pdf | `e2b5852b4d92f038ee67aa253138ff918d19d95527fc38b811aa28ea951375d7` | embedded WANConnectionDevice of IGDv1 |
| WANCD2 | WANConnectionDevice:2 | http://upnp.org/specs/gw/UPnP-gw-WANConnectionDevice-v2-Device.pdf | `8ffe61f9f4a863a6adf25874d6b9899d21eb0c7b56b45400c3435e4544656695` | embedded WANConnectionDevice of IGDv2 (holds WANIPv6FirewallControl) |
| WANIPC1 | WANIPConnection:1 | http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v1-Service.pdf | `dd2991a7ac67d9b225280c8c118719b7f817ee9c31eb3c128791ac1867e5addd` | the v1 actions (§2.4.x) and errors (713-727, §2.4.21 common codes) |
| WANIPC2 | WANIPConnection:2 | http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf | `c73edcd1d42f43b90bef6cb963eff6620542125bec74d21ae4252a0180275359` | the v2 actions (§2.5.x: AddAnyPortMapping, DeletePortMappingRange, GetListOfPortMappings), lease 0 = 604800 (§2.3.16), 606 and 728-733 |
| WANCIC1 | WANCommonInterfaceConfig:1 | http://upnp.org/specs/gw/UPnP-gw-WANCommonInterfaceConfig-v1-Service.pdf | `0393e59794ed1a13689a513877fef7e8100ad898a44294643dea676df33e5e99` | GetCommonLinkProperties, GetTotal* counters (§2.4.3, §2.4.6-§2.4.9) |
| L3F1 | Layer3Forwarding:1 | http://upnp.org/specs/gw/UPnP-gw-Layer3Forwarding-v1-Service.pdf | `afa97f003252283e472e7d5a9fc0f11ae49fbc6def561c6eb7a0611a6dba1694` | Get/SetDefaultConnectionService (§2.4.1, §2.4.2) |
| 6FC1 | WANIPv6FirewallControl:1 | http://upnp.org/specs/gw/UPnP-gw-WANIPv6FirewallControl-v1-Service.pdf | `d463fe6d25ae54596b8d039991113d4b3a461ad2ae48ed241dc1779e522a57f5` | pinholes (§2.6.1-§2.6.7), lease range 1-86400 (§2.4.8), errors 606 and 701-709 (§2.6.9) |
| DP1 | DeviceProtection:1 | http://upnp.org/specs/gw/UPnP-gw-DeviceProtection-v1-Service.pdf | `5899e1c7b6163555644b3c2e8cedc050b4c046dc1892cd020115298cad8e88bb` | DeviceProtection (§2.6.1-§2.6.3); not built by configure (ENABLE_DP_SERVICE stays commented out) |
| RFC6970 | UPnP IGD-PCP Interworking | https://www.rfc-editor.org/rfc/rfc6970.txt | `1511c0a22f6dd427e24d79645ebd02e576a39d94276d6230d279651585f25c5e` | UPnP and PCP mappings on one port (upnp_e2e) |
| RFC9112 | HTTP/1.1 | https://www.rfc-editor.org/rfc/rfc9112.txt | `e4f426bac6206b67fdf9e0da826154f70588db2133a0a86b15cde4ff725d8937` | request line (§3), Host (§3.2), Content-Length (§6.2, §6.3), chunked (§7.1), persistence (§9.3) |
| SOAP11 | SOAP 1.1 (W3C Note) | https://www.w3.org/TR/2000/NOTE-SOAP-20000508/ | `8e2a57ff110448f48d3b96f8a589524064d3679c87ddc9387cc8f74e0787efbe` | envelope namespace and faults (§4, §4.4), SOAPAction header (§6.1.1) |
