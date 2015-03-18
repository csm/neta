Network Analyzer is a Cocoa-native implementation of a protocol sniffer/traffic analyzer tool, similar in purpose and design to Wireshark. Network Analyzer uses the pcap library for packet capture.

Network Analyzer is currently in a very early stage of development; the basic functionality is there, but there is a whole lot more left to be done. See the ToDoList for a list of open tasks.

Help is appreciated on this project! We need to write more code, but we also appreciate any comments about the interface of the program (see also the [UIDetails](UIDetails.md) page) and would greatly appreciate some better icons. Another great way to help out is to write a 'dissector' plugin for your favorite protocol using the [PluginAPIDesign](PluginAPIDesign.md) of Network Analyzer.