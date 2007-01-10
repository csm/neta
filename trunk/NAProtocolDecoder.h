/* NAProtocolDecoder.h -- protocol decoder.
   Copyright (C) 2007  Casey Marshall <casey.s.marshall@gmail.com>

This file is a part of Network Analyzer.

Network Analyzer is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301  USA

Linking Network Analyzer statically or dynamically with other modules
is making a combined work based on Network Analyzer.  Thus, the terms
and conditions of the GNU General Public License cover the whole
combination.

In addition, as a special exception, the copyright holders of Network
Analyzer give you permission to combine Network Analyzer with free
software programs or libraries that are released under the GNU LGPL
and with independent modules that communicate with Network Analyzer
solely through the NAPlugin.framework interface. You may copy and
distribute such a system following the terms of the GNU GPL for
Network Analyzer and the licenses of the other code concerned, provided
that you include the source code of that other code when and as the
GNU GPL requires distribution of source code.

Note that people who make modified versions of Network Analyzer are not
obligated to grant this special exception for their modified versions;
it is their choice whether to do so.  The GNU General Public License
gives permission to release a modified version without this exception;
this exception also makes it possible to release a modified version
which carries forward this exception.  */

#import <Cocoa/Cocoa.h>

typedef NSString NAProtocolID;

#define kNAProtocolIdentityIP   @"ip"
#define kNAProtocolIdentityIPv6 @"ip6"
#define kNAProtocolIdentityARP  @"arp"
#define kNAProtocolIdentityTCP  @"tcp"
#define kNAProtocolIdentityUDP  @"udp"

@protocol NAProtocolDecoder

// Returns this protocol's identifier.
//
// The format of protocol identifiers is a dotted hierarchy:
//
//   ip       Is the Internet Protocol (version 4)
//   ip.tcp   Is the Transmission Control Protocol, running on the Internet
//            protocol.
//   ip.tcp.http  Is the Hypertext Transfer Protocol.
//
// and so on. A particular decoder plugin will simply return its protocol
// name, so an HTTP decoder returns the identifier "http", the TCP decoder
// returns "tcp", and so on.
//
+ (const NAProtocolID *) identifier;

// Returns a list of possible parent protocol decoders. Every element of the
// returned array must be a NAProtocolID *.
//
+ (NSArray *) parentProtocols;

- (void) setData: (NSData *) theData;
- (NSString *) summarize;
- (NSArray *) decode;
- (BOOL) validateChild: (Class) aClass;
- (NSData *) payload;
- (unsigned) headerLength;

+ (BOOL) match: (NSData *) theData;

+ (NSString *) pluginInfo;

@end