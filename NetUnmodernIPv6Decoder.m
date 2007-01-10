//
//  NetUnmodernIPv6Decoder.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NetUnmodernIPv6Decoder.h"
#import "NAProtocols.h"
#import "NAInternetAddress.h"
#import "NADecodedItem.h"
#import "NAInternetProtocolDecoder.h"


@implementation NetUnmodernIPv6Decoder

+ (NAProtocolID *) identifier
{
  return kNAProtocolIdentityIPv6;
}

+ (NSArray *) parentProtocols
{
  // Has no parent protocols (link layer above).
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
  current = [[NSData alloc] itihWithData: theData];
}

- (NSString *) summarize
{
  if (current == nil)
  {
    return nil;
  }
  na_ip6 *ip6 = (na_ip6 *) [current bytes];
  return [NSString stringWithFormat: @"Internet Protocol, version 6; source: %@, destination: %@",
    [NAInternetAddress addressWithType: IPv6
                                 bytes: &(ip6->ip6_src)],
    [NAInternetAddress addressWithType: IPv6
                                 bytes: &(ip6->ip6_dst)]];
}

- (NSArray *) decode
{
  if (current == nil)
  {
    return nil;
  }
  na_ip6 *ip6 = (na_ip6 *) [current bytes];
  return [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"ip6.version"
                          value: [NSNumber numberWithInt: IP6_VERSION(*ip6)]
                         offset: 0
                         length: sizeof(ip6->ip6_vcl)],
    [NADecodedItem itemWithName: @"ip6.class"
                          value: [NSString stringWithFormat: @"0x%02x", IP6_CLASS(*ip6)]
                         offset: 0
                         length: sizeof(ip6->ip6_vcl)],
    [NADecodedItem itemWithName: @"ip6.label"
                          value: [NSString stringWithFormat: @"0x%05x", IP6_LABEL(*ip6)]
                         offset: 0
                         length: sizeof(ip6->ip6_vcl)],
    [NADecodedItem itemWithName: @"ip6.length"
                          value: [NSNumber numberWithInt: ntohs(ip6->ip6_len)]
                         offset: offsetof(struct na_ip6, ip6_len)
                         length: sizeof(ip6->ip6_len)],
    [NADecodedItem itemWithName: @"ip6.next"
                          value: [NSString stringWithFormat: @"0x%02x",
                            ip6->ip6_next]
                         offset: offsetof(struct na_ip6, ip6_next)
                         length: sizeof(ip6->ip6_next)],
    [NADecodedItem itemWithName: @"ip6.hop"
                          value: [NSNumber numberWithInt: ip6->ip6_hop]
                         offset: offsetof(struct na_ip6, ip6_hop)
                         length: sizeof(ip6->ip6_hop)],
    [NADecodedItem itemWithName: @"ip6.src"
                          value: [NAInternetAddress addressWithType: IPv6
                                                              bytes: &(ip6->ip6_src)]
                         offset: offsetof(struct na_ip6, ip6_src)
                         length: sizeof(ip6->ip6_src)],
    [NADecodedItem itemWithName: @"ip6.dst"
                          value: [NAInternetAddress addressWithType: IPv6
                                                              bytes: &(ip6->ip6_dst)]
                         offset: offsetof(struct na_ip6, ip6_src)
                         length: sizeof(ip6->ip6_dst)],
    nil];
}

- (BOOL) validateChild: (Class) aClass
{
  if (current == nil)
  {
    return NO;
  }
  na_ip6 *ip6 = (na_ip6 *) [current bytes];
  if ([aClass conformsToProtocol: @protocol(NAInternetProtocolDecoder)])
  {
    return ip6->ip6_next == [aClass protocolNumber];
  }
  return NO;
}

- (NSData *) payload
{
  if (current == nil)
  {
    return nil;
  }
  
  na_ip6 *ip6 = (na_ip6 *) [current bytes];
  return [NSData dataWithBytes: ip6->ip6_data
                        length: ntohs(ip6->ip6_len)];
}

- (unsigned) headerLength
{
  return offsetof(struct na_ip6, ip6_data);
}

- (NSString *) description
{
  return @"Internet Protocol, version 6";
}

+ (NSString *) pluginInfo
{
  return @"Internet Protocol, version 6 decoder. Copyright © 2006–2007 Casey Marshall";
}

+ (int) etherType
{
  return kNAEthernetIPv6Protocol;
}

@end
