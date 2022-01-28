
mdns2bcast
==========

Converts multicast DNS (mDNS) into broadcast packets.

My stupid router (a Sagemcom F@st 3686) does not properly handle mDNS, and queries generated on
LAN devices are not properly forwarded to wireless stations, due to a flawed multicast-to-unicast
implementation.

This daemon is a workaround that listens to mDNS queries and converts them into illegal Ethernet
frames, whose MAC address is the broadcast one despite containing a multicast IP packet.

These broadcast frames are properly streamed across the network, and thus mDNS responders receive
them successfully.
