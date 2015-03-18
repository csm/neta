# General #

Customizable layout, like Wireshark? (i.e., different placements of the three panes).

# Packets table #

Probably a straightforward NSTableView, with columns for

  * Date. In seconds, or readable date? (2006-12-25 18:11:32)
  * Source/dest in ether address, IP address, something else, if appropriate.

Customizable layout?

Copy here will copy the whole captured packet. Multiple selection will copy multiple packets.

# Packet detail outline #

I'm thinking just similar to Wireshark here: one line per protocol level, and the disclosure triangle expands the details for that protocol. This should be a straightforward data model for NSOutlineView.

Parts are selectable, and copy here selects those parts of the packet.

Also, selecting a line in this view selects the same parts of the packet in the hex view below.

  * Packet details uses coloring similar to the thread coloring in Mail.app: the main grouping of a decoded packet item is colored blue, and the packet details (when expanded) have a lighter blue background, and have a blue column on the left hand side. This is implemented, and I think it looks really nice. It is useful, too, because you can see the protocol layer separation, and the extent of a layer (or sub-layer) quickly.

# Packet detail hex #

This will probably be a three-column text view, split into offset, hex bytes, then "printable" bytes (similar output to 'hexdump -C'). Selection is the interesting thing: if you select one of the two data columns, that will also select the same data in the other data column. Maybe selecting the offset column selects that whole "line".

Copying here selects _parts_ of the packet.