/* NetUnmodernARPDecoder.m -- address resolution protocol decoder.
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


#import "NetUnmodernARPDecoder.h"
#import "NADecodedItem.h"
#import "NAProtocols.h"
#import "NAUtils.h"


@implementation NetUnmodernARPDecoder

+ (const NAProtocolID *) identifier
{
  return @"arp";
}

+ (NSArray *) parentProtocols
{
  return nil;
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

- (NADecodedPacketSummary *) summarize
{
  if (current == nil)
  {
    return nil;
  }

  na_arp *arp = (na_arp *) [current bytes];
  NSString *srch = [NAUtils toHexString: ARP_SHA(*arp)
                                 length: arp->arp_hlen
                              separator: @":"];
  NSString *srcp = nil;
  if (arp->arp_plen == 4)
  {
    srcp = [NSString stringWithFormat: @"%d.%d.%d.%d",
      ARP_SPA(*arp)[0] & 0xFF, ARP_SPA(*arp)[1] & 0xFF,
      ARP_SPA(*arp)[2] & 0xFF, ARP_SPA(*arp)[3] & 0xFF];
  }
  else
  {
    srcp = [NAUtils toHexString: ARP_SPA(*arp)
                         length: arp->arp_plen
                      separator: @":"];
  }

  NSString *dsth = [NAUtils toHexString: ARP_THA(*arp)
                                 length: arp->arp_hlen
                              separator: @":"];
  NSString *dstp = nil;
  if (arp->arp_plen == 4)
  {
    dstp = [NSString stringWithFormat: @"%d.%d.%d.%d",
      ARP_TPA(*arp)[0] & 0xFF, ARP_TPA(*arp)[1] & 0xFF,
      ARP_TPA(*arp)[2] & 0xFF, ARP_TPA(*arp)[3] & 0xFF];
  }
  else
  {
    dstp = [NAUtils toHexString: ARP_TPA(*arp)
                         length: arp->arp_plen
                      separator: @":"];
  }
  NSString *desc = nil;
  if (ntohs(arp->arp_operation) == 1)
  {
    desc = [NSString stringWithFormat: @"who-has %@ tell %@",
      dstp, srch];
  }
  else if (ntohs(arp->arp_operation) == 2)
  {
    desc = [NSString stringWithFormat: @"%@ is-at %@",
      srcp, srch];
  }
  else
  {
    desc = [NSString stringWithFormat: @"ARP operation %d",
      ntohs(arp->arp_operation)];
  }
  return [NADecodedPacketSummary summaryWithSource: srch
                                       destination: dsth
                                          protocol: @"ARP"
                                           summary: desc];
}

- (NSArray *) decode
{
  if (current == nil)
  {
    return nil;
  }
  na_arp *arp = (na_arp *) [current bytes];
  return [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"arp.htype"
                          value: [NSString stringWithFormat: @"0x04x",
                            ntohl(arp->arp_htype)]
                         offset: offsetof(struct na_arp, arp_htype)
                         length: sizeof(arp->arp_htype)],
    [NADecodedItem itemWithName: @"arp.ptype"
                          value: [NSString stringWithFormat: @"0x04x",
                            ntohl(arp->arp_ptype)]
                         offset: offsetof(struct na_arp, arp_ptype)
                         length: sizeof(arp->arp_ptype)],
    [NADecodedItem itemWithName: @"arp.hlen"
                          value: [NSNumber numberWithInt: arp->arp_hlen]
                         offset: offsetof(struct na_arp, arp_hlen)
                         length: sizeof(arp->arp_hlen)],
    [NADecodedItem itemWithName: @"arp.plen"
                          value: [NSNumber numberWithInt: arp->arp_plen]
                         offset: offsetof(struct na_arp, arp_plen)
                         length: sizeof(arp->arp_plen)],
    [NADecodedItem itemWithName: @"arp.op"
                          value: [NSString stringWithFormat: @"0x%04x",
                            ntohs(arp->arp_operation)]
                         offset: offsetof(struct na_arp, arp_operation)
                         length: sizeof(arp->arp_operation)],
    [NADecodedItem itemWithName: @"arp.sha"
                          value: [NAUtils toHexString: ARP_SHA(*arp)
                                              length: arp->arp_hlen
                                           separator: @":"]
                         offset: offsetof(struct na_arp, arp_sha)
                         length: arp->arp_hlen],
    [NADecodedItem itemWithName: @"arp.spa"
                          value: [NAUtils toHexString: ARP_SPA(*arp)
                                              length: arp->arp_plen
                                           separator: @":"]
                         offset: (offsetof(struct na_arp, arp_sha)
                                  + arp->arp_hlen)
                         length: arp->arp_plen],
    [NADecodedItem itemWithName: @"arp.tha"
                          value: [NAUtils toHexString: ARP_THA(*arp)
                                              length: arp->arp_hlen
                                           separator: @":"]
                         offset: (offsetof(struct na_arp, arp_sha)
                                  + arp->arp_hlen + arp->arp_plen)
                         length: arp->arp_hlen],
    [NADecodedItem itemWithName: @"arp.tpa"
                          value: [NAUtils toHexString: ARP_TPA(*arp)
                                              length: arp->arp_plen
                                           separator: @":"]
                         offset: (offsetof(struct na_arp, arp_sha)
                                  + (2 * arp->arp_hlen) + arp->arp_plen)
                         length: arp->arp_plen],
    nil];
}

- (BOOL) validateChild: (Class) aClass
{
  return NO; // never has more data.
}

- (NSData *) payload
{
  return nil;
}

- (unsigned) headerLength
{
  return sizeof(struct na_arp);
}

+ (NSString *) pluginInfo
{
  return @"Address Resolution Protocol decoder. Copyright (C) 2007 Casey Marshall.";
}

+ (int) etherType
{
  return kNAEthernetARPProtocol;
}

@end
