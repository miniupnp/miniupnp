# PCP_TEST_CONF_REPLACE (entrypoint.sh) and daemon_options/freebsd/run-suite.sh: print the second
# file, the default miniupnpd.conf, without the lines that the first one, a test's extra lines,
# replaces:
#
#   awk -f conf_replace.awk EXTRA DEFAULT
#
# A key=value line replaces the line of the same option: miniupnpd does not let a later line undo
# an earlier one for its flags (enable_upnp=yes after enable_upnp=no, enable_pcp_pmp=no after
# enable_pcp_pmp=yes). enable_natpmp / enable_pcp_pmp and port / http_port are one option each, and
# key=@OFF@ replaces it with nothing (entrypoint.sh drops that line). An allow / deny line replaces
# all the default ones: the first matching line decides.
function option(line) {
	sub(/=.*/, "", line); gsub(/[ \t]/, "", line)
	if (line == "enable_natpmp") return "enable_pcp_pmp"
	if (line == "http_port") return "port"
	return line
}
NR == FNR {
	if (index($0, "=")) replaced[option($0)] = 1
	if ($1 == "allow" || $1 == "deny") permissions = 1
	next
}
!(index($0, "=") && (option($0) in replaced)) && !(permissions && ($1 == "allow" || $1 == "deny"))
