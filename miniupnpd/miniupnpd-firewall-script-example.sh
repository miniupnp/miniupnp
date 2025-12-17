#!/bin/bash
# Example external script for miniupnpd firewall management
# This script demonstrates how to handle miniupnpd firewall operations
# when use_external_script is enabled.
#
# Usage: miniupnpd-firewall.sh <operation> [arguments...]
#
# Operations:
#   add_redirect <ifname> <rhost> <eport> <iaddr> <iport> <proto> <desc> <timestamp>
#   add_filter <ifname> <rhost> <iaddr> <eport> <iport> <proto> <desc>
#   delete_redirect <ifname> <eport> <proto>
#   delete_filter <ifname> <eport> <proto>
#   delete_redirect_and_filter <eport> <proto>

set -e

OPERATION="$1"
shift

# Log function for debugging
log() {
    logger -t miniupnpd-script "$@"
}

# Function to add port forwarding (DNAT) rule
add_redirect() {
    local ifname="$1"
    local rhost="$2"
    local eport="$3"
    local iaddr="$4"
    local iport="$5"
    local proto="$6"
    local desc="$7"
    local timestamp="$8"
    
    log "Adding redirect: $proto $eport -> $iaddr:$iport (rhost: $rhost, desc: $desc)"
    
    # Example using iptables
    # Add your custom logic here
    # iptables -t nat -A PREROUTING -i "$ifname" -p "${proto,,}" --dport "$eport" -j DNAT --to-destination "$iaddr:$iport"
    
    # Example using nftables
    # nft add rule ip nat prerouting iifname "$ifname" "$proto" dport "$eport" dnat to "$iaddr:$iport"
    
    # Your custom implementation here
    echo "Add redirect: $proto $eport -> $iaddr:$iport" >&2
    
    return 0
}

# Function to add filter rule (FORWARD chain)
add_filter() {
    local ifname="$1"
    local rhost="$2"
    local iaddr="$3"
    local eport="$4"
    local iport="$5"
    local proto="$6"
    local desc="$7"
    
    log "Adding filter: $proto -> $iaddr:$iport (rhost: $rhost, desc: $desc)"
    
    # Example using iptables
    # iptables -t filter -A FORWARD -i "$ifname" -p "${proto,,}" -d "$iaddr" --dport "$iport" -j ACCEPT
    
    # Example using nftables
    # nft add rule ip filter forward iifname "$ifname" "$proto" daddr "$iaddr" dport "$iport" accept
    
    # Your custom implementation here
    echo "Add filter: $proto -> $iaddr:$iport" >&2
    
    return 0
}

# Function to delete port forwarding rule
delete_redirect() {
    local ifname="$1"
    local eport="$2"
    local proto="$3"
    
    log "Deleting redirect: $proto $eport"
    
    # Example using iptables
    # Find and delete the matching rule
    # iptables -t nat -D PREROUTING -i "$ifname" -p "${proto,,}" --dport "$eport" -j DNAT
    
    # Example using nftables
    # You'll need to track rule handles or search for matching rules
    
    # Your custom implementation here
    echo "Delete redirect: $proto $eport" >&2
    
    return 0
}

# Function to delete filter rule
delete_filter() {
    local ifname="$1"
    local eport="$2"
    local proto="$3"
    
    log "Deleting filter: $proto $eport"
    
    # Example using iptables
    # iptables -t filter -D FORWARD -i "$ifname" -p "${proto,,}" --dport "$eport" -j ACCEPT
    
    # Example using nftables
    # nft delete rule matching criteria
    
    # Your custom implementation here
    echo "Delete filter: $proto $eport" >&2
    
    return 0
}

# Function to delete both redirect and filter rules
delete_redirect_and_filter() {
    local eport="$1"
    local proto="$2"
    
    log "Deleting redirect and filter: $proto $eport"
    
    # Delete both NAT and filter rules
    # Your custom implementation here
    echo "Delete redirect and filter: $proto $eport" >&2
    
    return 0
}

# Main dispatcher
case "$OPERATION" in
    add_redirect)
        add_redirect "$@"
        ;;
    add_filter)
        add_filter "$@"
        ;;
    delete_redirect)
        delete_redirect "$@"
        ;;
    delete_filter)
        delete_filter "$@"
        ;;
    delete_redirect_and_filter)
        delete_redirect_and_filter "$@"
        ;;
    *)
        echo "Unknown operation: $OPERATION" >&2
        exit 1
        ;;
esac

exit 0
