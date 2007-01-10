/* NetUnmodernTCPDecoder.m -- TCP decoder.
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
02110-1301  USA  */


#import "NetUnmodernTCPDecoder.h"
#import "NAProtocols.h"
#import "NADecodedItem.h"

@implementation NetUnmodernTCPDecoder

+ (int) protocolNumber
{
  return kNAInternetProtocolNumberTCP;
}

+ (const NAProtocolID *) identifier
{
  return @"tcp";
}

+ (NSArray *) parentProtocols
{
  return [NSArray arrayWithObjects: kNAProtocolIdentityIP,
    kNAProtocolIdentityIPv6, nil];
}

- (id) init
{
  if ((self = [super init]) != nil)
  {
    current = nil;
  }

  return self;
}

- (void) setData: (NSData *) theData
{
  if (current != nil)
  {
    [current release];
  }
  current = [[NSData alloc] initWithData: theData];
}

- (NSString *) summarize
{
  if (current == nil)
  {
    return nil;
  }
  na_tcp *tcp = (na_tcp *) [current bytes];
  return [NSString stringWithFormat: @"Source port: %d; Destination port: %d",
    ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport)];
}

- (NSArray *) decode
{
  if (current == nil)
  {
    return nil;
  }
  na_tcp *tcp = (na_tcp *) [current bytes];
  NSArray *tcp_flags = [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"tcp.flags.cwr"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_CWR) == TCP_FLAG_CWR)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.flags.ece"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_ECE) == TCP_FLAG_ECE)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.flags.urg"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_URG) == TCP_FLAG_URG)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.flags.ack"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_ACK) == TCP_FLAG_ACK)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.flags.psh"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_PSH) == TCP_FLAG_PSH)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.flags.rst"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_RST) == TCP_FLAG_RST)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.flags.syn"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_SYN) == TCP_FLAG_SYN)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.flags.fin"
                          value: [NSNumber numberWithBool:
                            ((tcp->tcp_flags & TCP_FLAG_FIN) == TCP_FLAG_FIN)]
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    nil];

  return [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"tcp.src"
                          value: [NSNumber numberWithInt: ntohs(tcp->tcp_sport)]
                         offset: offsetof(struct na_tcp, tcp_sport)
                         length: sizeof(tcp->tcp_sport)],
    [NADecodedItem itemWithName: @"tcp.dst"
                          value: [NSNumber numberWithInt: ntohs(tcp->tcp_dport)]
                         offset: offsetof(struct na_tcp, tcp_dport)
                         length: sizeof(tcp->tcp_dport)],
    [NADecodedItem itemWithName: @"tcp.seq"
                          value: [NSNumber numberWithInt: ntohl(tcp->tcp_seq)]
                         offset: offsetof(struct na_tcp, tcp_seq)
                         length: sizeof(tcp->tcp_seq)],
    [NADecodedItem itemWithName: @"tcp.ack"
                          value: [NSNumber numberWithInt: ntohl(tcp->tcp_ack)]
                         offset: offsetof(struct na_tcp, tcp_ack)
                         length: sizeof(tcp->tcp_ack)],
    [NADecodedItem itemWithName: @"tcp.doff"
                          value: [NSNumber numberWithInt: TCP_DATA_OFFSET(*tcp)]
                         offset: offsetof(struct na_tcp, tcp_doff)
                         length: sizeof(tcp->tcp_doff)],
    [NADecodedItem itemWithName: @"tcp.flags"
                          value: tcp_flags
                         offset: offsetof(struct na_tcp, tcp_flags)
                         length: sizeof(tcp->tcp_flags)],
    [NADecodedItem itemWithName: @"tcp.window"
                          value: [NSNumber numberWithInt: ntohs(tcp->tcp_window)]
                         offset: offsetof(struct na_tcp, tcp_window)
                         length: sizeof(tcp->tcp_window)],
    [NADecodedItem itemWithName: @"tcp.checksum"
                          value: [NSString stringWithFormat: @"0x%04x",
                            ntohs(tcp->tcp_csum)]
                         offset: offsetof(struct na_tcp, tcp_csum)
                         length: sizeof(tcp->tcp_csum)],
    [NADecodedItem itemWithName: @"tcp.urg"
                          value: [NSString stringWithFormat: @"0x%04x",
                            ntohs(tcp->tcp_urg)]
                         offset: offsetof(struct na_tcp, tcp_urg)
                         length: sizeof(tcp->tcp_urg)],
    nil];
}

- (BOOL) validateChild: (Class) aClass
{
  return NO; // FIXME
}

- (NSData *) payload
{
  return nil; // FIXME
}

- (unsigned) headerLength
{
  return 0; // FIXME
}

- (NSString *) description
{
  return @"Transmission Control Protocol";
}

+ (NSString *) pluginInfo
{
  return @"Transmission Control Protocol decoder. Copyright © 2006–2007 Casey Marshall";
}

@end
