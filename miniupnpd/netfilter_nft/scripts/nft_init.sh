#!/bin/sh
#
# establish the chains that miniupnpd will update dynamically
#
# 'add' doesn't raise an error if the object already exists. 'create' does.
#

. "$(dirname "$0")/miniupnpd_functions.sh"

$NFT --check list table inet $TABLE > /dev/null 2>&1
if [ $? -eq "0" ]
then
echo "Table $TABLE already exists"
exit 0
fi

echo "Creating nftables structure"

firewallinit="
table inet $TABLE {
    chain forward {
        type filter hook forward priority 0;
        policy drop;

        # miniupnpd
        jump $CHAIN

        # Add other rules here
    }

    # miniupnpd
    chain $CHAIN {
    }

"

if [ "$TABLE" != "$NAT_TABLE" ]
then
firewallinit="${firewallinit}
}

table inet $NAT_TABLE {
"
fi

firewallinit="${firewallinit}
    chain prerouting {
        type nat hook prerouting priority -100;
        policy accept;

        # miniupnpd
        jump $PREROUTING_CHAIN

        # Add other rules here
    }

    chain postrouting {
        type nat hook postrouting priority 100;
        policy accept;

        # miniupnpd
        jump $POSTROUTING_CHAIN

        # Add other rules here
    }

    chain $PREROUTING_CHAIN {
    }

    chain $POSTROUTING_CHAIN {
    }
}
"

echo "$firewallinit" | $NFT -f -
