### QoS (Quality of service) ###

This is a Linux bash script that will set up tc to limit the outgoing bandwidth for connections to the Bitcoin network. It limits outbound TCP traffic with a source or destination port of 8338, but not if the destination IP is within a LAN.

This means one can have an always-on fjarcoded instance running, and another local fjarcoded/fjarcode-qt instance which connects to this node and receives blocks from it.
