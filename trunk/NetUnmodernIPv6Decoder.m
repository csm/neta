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

- (NSArray *) decodeData: (NSData *) theData
{
  na_ip6 *ip6 = (na_ip6 *) [theData bytes];
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
    nil]; // FIXME
}

- (NSString *) description
{
  return @"Internet Protocol, version 6";
}

@end
