# External Script Support for MiniUPnPd (Linux only)

## Overview

This feature allows you to completely disable miniupnpd's direct manipulation of iptables/nftables and instead have it call an external script to handle firewall operations. This is useful when:

- You have a custom firewall management system
- You want full control over firewall rule implementation
- You need to integrate with third-party firewall solutions
- You want to add custom logging or validation logic

## Building and Installation

### Prerequisites
- Linux system with nftables support
- Build tools: gcc, make
- Debian packaging tools (for .deb creation): dpkg-deb

### Build Instructions

1. **Configure and compile:**
   ```bash
   make clean
   ./configure --firewall=nftables && make
   ```

2. **Create Debian package (optional):**
   ```bash
   ./build.sh
   ```
   This will:
   - Clean and compile with nftables support
   - Copy the binary to the package structure
   - Create `miniupnpd-custom.deb`

3. **Install the package:**
   ```bash
   sudo dpkg -i miniupnpd-custom.deb
   ```

## Configuration

Add the following options to your `miniupnpd.conf`:

```ini
# Enable external script mode (REQUIRED)
use_external_script=yes

# Path to your firewall management script (REQUIRED)
external_script_path=/usr/local/bin/miniupnpd-firewall.sh
```

**Important:** Both options must be present in the configuration file for the external script feature to work. If `use_external_script=yes` is set but `external_script_path` is missing or empty, miniupnpd will log an error and fail to process port mapping requests.

After modifying the configuration, restart the service:
```bash
sudo systemctl restart miniupnpd
```

Verify the configuration was loaded correctly:
```bash
sudo journalctl -u miniupnpd | grep -i "external script"
```

You should see messages like:
```
miniupnpd: external script mode: enabled
miniupnpd: external script path: /usr/local/bin/miniupnpd-firewall.sh
```

## Script Interface

Your script will be called with different operations and arguments:

### Operations

#### 1. add_redirect
Called when a port forwarding rule needs to be added.

**Arguments:**
```
add_redirect <ifname> <rhost> <eport> <iaddr> <iport> <proto> <desc> <timestamp>
```

- `ifname`: External network interface name (e.g., "eth0")
- `rhost`: Remote host IP address or "*" for any host
- `eport`: External port number
- `iaddr`: Internal IP address to forward to
- `iport`: Internal port number
- `proto`: Protocol - "TCP", "UDP", or "UDPLITE"
- `desc`: Description of the port mapping
- `timestamp`: Lease expiration timestamp (0 for permanent mapping)

**Example:**
```bash
add_redirect eth0 * 8080 192.168.1.100 80 TCP "Web Server" 1734480000
```

#### 2. add_filter
Called when a filter rule needs to be added to allow forwarded traffic.

**Arguments:**
```
add_filter <ifname> <rhost> <iaddr> <eport> <iport> <proto> <desc>
```

**Example:**
```bash
add_filter eth0 * 192.168.1.100 8080 80 TCP "Web Server"
```

#### 3. delete_redirect
Called when a port forwarding rule needs to be removed.

**Arguments:**
```
delete_redirect <ifname> <eport> <proto>
```

**Example:**
```bash
delete_redirect eth0 8080 TCP
```

#### 4. delete_filter
Called when a filter rule needs to be removed.

**Arguments:**
```
delete_filter <ifname> <eport> <proto>
```

**Example:**
```bash
delete_filter eth0 8080 TCP
```

#### 5. delete_redirect_and_filter
Called to remove both redirect and filter rules at once (Linux optimization).

**Arguments:**
```
delete_redirect_and_filter <eport> <proto>
```

**Example:**
```bash
delete_redirect_and_filter 8080 TCP
```

## Script Requirements

Your script MUST:

1. **Be executable** (`chmod +x your-script.sh`)
2. **Exit with status 0** on success
3. **Exit with non-zero status** on failure
4. **Handle all five operations** listed above
5. **Be idempotent** where possible (handle cases where rules already exist or don't exist)
6. **Avoid using `logger` command** - The `logger` command may hang when called from systemd context. Use file logging or echo to stdout/stderr instead:
   ```bash
   # Good - log to file
   log() {
       echo "[$(date)] $@" >> /var/log/miniupnpd-script.log
   }
   
   # Bad - may hang under systemd
   log() {
       logger -t miniupnpd "$@"
   }
   ```

## Example Implementation

See `miniupnpd-firewall-script-example.sh` for a complete example script template.

### Basic iptables Example

```bash
#!/bin/bash
set -e

OPERATION="$1"
shift

case "$OPERATION" in
    add_redirect)
        ifname="$1"
        rhost="$2"
        eport="$3"
        iaddr="$4"
        iport="$5"
        proto="$6"
        
        iptables -t nat -A MINIUPNPD -i "$ifname" -p "${proto,,}" --dport "$eport" \
            -j DNAT --to-destination "$iaddr:$iport"
        ;;
        
    add_filter)
        ifname="$1"
        rhost="$2"
        iaddr="$3"
        eport="$4"
        iport="$5"
        proto="$6"
        
        iptables -A MINIUPNPD -i "$ifname" -p "${proto,,}" -d "$iaddr" \
            --dport "$iport" -j ACCEPT
        ;;
        
    delete_redirect_and_filter)
        eport="$1"
        proto="$2"
        
        # Delete NAT rule
        iptables -t nat -D MINIUPNPD -p "${proto,,}" --dport "$eport" -j DNAT 2>/dev/null || true
        
        # Delete filter rule
        iptables -D MINIUPNPD -p "${proto,,}" --dport "$eport" -j ACCEPT 2>/dev/null || true
        ;;
esac

exit 0
```

## Testing

1. Enable the feature in `miniupnpd.conf`
2. Create your script and make it executable
3. Start miniupnpd with your configuration
4. Test by requesting a port mapping from a UPnP client
5. Check system logs for script execution messages:
   ```bash
   journalctl -u miniupnpd -f
   ```

## Security Considerations

- **Validate input** in your script before executing firewall commands
- **Use absolute paths** for firewall commands (iptables, nft, etc.)
- **Run with minimal privileges** if possible
- **Log operations** for audit purposes
- **Handle errors gracefully** and return appropriate exit codes

## Debugging

Enable debug logging in miniupnpd to see when the script is called:

```bash
miniupnpd -d -f /etc/miniupnpd.conf
```

Check syslog for script execution details:
```bash
tail -f /var/log/syslog | grep miniupnpd
```

## Limitations

- This feature is **Linux-only** (USE_NETFILTER must be enabled at compile time)
- The script is called **synchronously**, so it should execute quickly
- **No query operations** are supported yet (like listing existing rules)
- The interface is **forward-compatible** but may be extended in future versions

## Performance

Each port mapping operation requires executing an external process. For high-volume scenarios:

- Use efficient firewall commands
- Consider batching operations in your script
- Minimize external dependencies
- Use compiled tools instead of interpreted scripts if needed

## Example Use Cases

1. **Custom firewall with API**: Script calls REST API of custom firewall appliance
2. **Database logging**: Record all port mapping operations to a database
3. **Advanced validation**: Implement business-specific port mapping policies
4. **Multi-firewall management**: Update multiple firewall systems simultaneously
5. **Cloud integration**: Update cloud provider security groups via API
