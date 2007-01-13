/* NetUnmodernUDPDecoder.m -- UDP decoder.
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


#import "NetUnmodernUDPDecoder.h"
#import "NAProtocols.h"
#import "NADecodedItem.h"
#import "NAUtils.h"


@implementation NetUnmodernUDPDecoder

+ (const NAProtocolID *) identifier
{
  return kNAProtocolIdentityUDP;
}

+ (NSArray *) parentProtocols
{
  return [NSArray arrayWithObjects:
    kNAProtocolIdentityIP,
    kNAProtocolIdentityIPv6,
    nil];
}

- (id) init
{
  if ((self = [super init]) != nil)
  {
    current = nil;
    source = nil;
    dest = nil;
  }
  
  return self;
}

- (void) setData: (NSData *) theData
{
  if (current != nil)
  {
    [current release];
  }
  if (source != nil)
  {
    [source release];
    source = nil;
  }
  if (dest != nil)
  {
    [dest release];
    dest = nil;
  }
  current = [[NSData alloc] initWithData: theData];
}

- (void) setSource: (NAInternetAddress *) aSource
       destination: (NAInternetAddress *) aDest
{
  if (source != nil)
  {
    [source release];
    source = nil;
  }
  if (dest != nil)
  {
    [dest release];
    dest = nil;
  }
  
  if (aSource != nil)
  {
    source = [[NAInternetAddress alloc] initWithAddress: aSource];
  }
  else
  {
    source = nil;
  }
  
  if (aDest != nil)
  {
    dest = [[NAInternetAddress alloc] initWithAddress: aDest];
  }
  else
  {
    dest = nil;
  }
}

- (NADecodedPacketSummary *) summarize
{
  if (current == nil)
  {
    return nil;
  }
  
  na_udp *udp = (na_udp *) [current bytes];
  NSString *src = nil;
  if (source != nil)
  {
    if ([source type] == IPv4)
    {
      src = [NSString stringWithFormat: @"%@:%d", source, ntohs(udp->udp_sport)];
    }
    else
    {
      src = [NSString stringWithFormat: @"[%@]:%d", source, ntohs(udp->udp_sport)];      
    }
  }
  else
  {
    src = [NSString stringWithFormat: @"%d", ntohs(udp->udp_sport)];
  }
  NSString *dst = nil;
  if (dest != nil)
  {
    if ([dest type] == IPv4)
    {
      dst = [NSString stringWithFormat: @"%@:%d", dest, ntohs(udp->udp_dport)];
    }
    else
    {
      dst = [NSString stringWithFormat: @"[%@]:%d", dest, ntohs(udp->udp_dport)];      
    }
  }
  else
  {
    dst = [NSString stringWithFormat: @"%d", ntohs(udp->udp_dport)];
  }
  NSString *desc = [NSString stringWithFormat:
    @"User datagram protocol; source: %@; destination: %@", src, dst];
  
  return [NADecodedPacketSummary summaryWithSource: src
                                       destination: dst
                                          protocol: @"UDP"
                                           summary: desc];
}

- (NSArray *) decode
{
  if (current == nil)
  {
    return nil;
  }
  
  na_udp *udp = (na_udp *) [current bytes];
  return [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"udp.src"
                          value: [NSNumber numberWithInt: ntohs(udp->udp_sport)]
                         offset: offsetof(struct na_udp, udp_sport)
                         length: sizeof(udp->udp_sport)],
    [NADecodedItem itemWithName: @"udp.dst"
                          value: [NSNumber numberWithInt: ntohs(udp->udp_dport)]
                         offset: offsetof(struct na_udp, udp_dport)
                         length: sizeof(udp->udp_dport)],
    [NADecodedItem itemWithName: @"udp.len"
                          value: [NSNumber numberWithInt: ntohs(udp->udp_length)]
                         offset: offsetof(struct na_udp, udp_length)
                         length: sizeof(udp->udp_length)],
    [NADecodedItem itemWithName: @"udp.checksum"
                          value: [NSNumber numberWithInt: ntohs(udp->udp_csum)]
                         offset: offsetof(struct na_udp, udp_csum)
                         length: sizeof(udp->udp_csum)],
    nil];
}

- (BOOL) validateChild: (Class) aClass
{
  return NO; // FIXME
}

- (NSData *) payload
{
  if (current == nil)
  {
    return nil;
  }
  na_udp *udp = (na_udp *) [current bytes];
#if DEBUG
  NSLog(@"%@", [NAUtils hexdump: current]);
  NSLog(@"payload: %p; length: %d", udp->udp_data, udp->udp_length);
#endif // DEBUG
  return [NSData dataWithBytes: udp->udp_data
                        length: ntohs(udp->udp_length) - 8];
}

- (unsigned) headerLength
{
  return 8;
}

+ (BOOL) match: (NSData *) theData
{
  return NO;
}

+ (NSString *) pluginInfo
{
  return @"User Datagram Protocol decoder. Copyright (C) 2007 Casey Marshall.";
}

+ (int) protocolNumber
{
  return kNAInternetProtocolNumberUDP;
}

@end
