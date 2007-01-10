//
//  NetUnmodernARPDecoder.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/8/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

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

- (NSString *) summarize
{
  if (current == nil)
  {
    return nil;
  }
  
  na_arp *arp = (na_arp *) [current bytes];
  if (arp->arp_operation == 1)
  {
    return [NSString stringWithFormat: @"who-has %@ tell %@",
      [NAUtils toHexString: ARP_TPA(*arp)
                    length: arp->arp_plen
                 separator: @":"],
      [NAUtils toHexString: ARP_SPA(*arp)
                    length: arp->arp_plen
                 separator: @":"]];
  }
  else if (arp->arp_operation == 2)
  {
    return [NSString stringWithFormat: @"%@ is-at %@",
      [NAUtils toHexString: ARP_SPA(*arp)
                    length: arp->arp_plen
                 separator: @":"],
      [NAUtils toHexString: ARP_SHA(*arp)
                    length: arp->arp_hlen
                 separator: @":"]];
  }
  return @"?";
}

- (NSArray *) decodeData: (NSData *) theData
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
                                              length: ntohs(arp->arp_hlen)
                                           separator: @":"]
                         offset: offsetof(struct na_arp, arp_sha)
                         length: ntohs(arp->arp_hlen)],
    [NADecodedItem itemWithName: @"arp.spa"
                          value: [NAUtils toHexString: ARP_SPA(*arp)
                                              length: ntohs(arp->arp_plen)
                                           separator: @":"]
                         offset: (offsetof(struct na_arp, arp_sha)
                                  + ntohs(arp->arp_hlen))
                         length: ntohs(arp->arp_plen)],
    [NADecodedItem itemWithName: @"arp.tha"
                          value: [NAUtils toHexString: ARP_THA(*arp)
                                              length: ntohs(arp->arp_hlen)
                                           separator: @":"]
                         offset: (offsetof(struct na_arp, arp_sha)
                                  + ntohs(arp->arp_hlen)
                                  + ntohs(arp->arp_plen))
                         length: ntohs(arp->arp_hlen)],
    [NADecodedItem itemWithName: @"arp.tpa"
                          value: [NAUtils toHexString: ARP_TPA(*arp)
                                              length: ntohs(arp->arp_plen)
                                           separator: @":"]
                         offset: (offsetof(struct na_arp, arp_sha)
                                  + (2 * ntohs(arp->arp_hlen))
                                  + ntohs(arp->arp_plen))
                         length: ntohs(arp->arp_plen)],
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
  return @"Address Resolution Protocol decoder. Copyright 2007 Casey Marshall.";
}

+ (int) etherType
{
  return kNAEthernetARPProtocol;
}

@end
