//
//  NetUnmodernIPProtocolDecoder.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NetUnmodernIPProtocolDecoder.h"
#import "NAProtocols.h"
#import "NAInternetAddress.h"
#import "NAPluginRegistry.h"
#import "NADecodedItem.h"

@implementation NetUnmodernIPProtocolDecoder

+ (const NAProtocolID *) identifier
{
  return @"ip";
}

+ (NSArray *) parentProtocols
{
  // Has no parent protocols (link layer above).
  return nil;
}

- (NSArray *) decodeData: (NSData *) theData
{
  na_ip *ip = (na_ip *) [theData bytes];
  NAInternetAddress *src = [NAInternetAddress addressWithType: IPv4
                                                        bytes: &(ip->ip_src)];
  NAInternetAddress *dst = [NAInternetAddress addressWithType: IPv4
                                                        bytes: &(ip->ip_dst)];
  int len = [theData length] - IP_HLEN(*ip);
  NSData *ipData = [NSData dataWithBytes: IP_GET_DATA(*ip) length: len];
  
  NSArray *ip_flags = [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"ip.flags.df"
                          value: [NSNumber numberWithInt: IP_FLAG_DF(*ip)]
                         offset: offsetof(struct na_ip, ip_ffoff)
                         length: sizeof(ip->ip_ffoff)],
    [NADecodedItem itemWithName: @"ip.flags.mf"
                          value: [NSNumber numberWithInt: IP_FLAG_MF(*ip)]
                         offset: offsetof(struct na_ip, ip_ffoff)
                         length: sizeof(ip->ip_ffoff)],
    nil];
    
  return [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"ip.version"
                          value: [NSNumber numberWithInt: IP_VERSION(*ip)]
                         offset: 0
                         length: sizeof(ip->ip_vl)],
    [NADecodedItem itemWithName: @"ip.hlen"
                          value: [NSNumber numberWithInt: IP_HLEN(*ip)]
                         offset: 0
                         length: sizeof(ip->ip_vl)],
    [NADecodedItem itemWithName: @"ip.tos"
                          value: [NSString stringWithFormat: @"0x%02x", ip->ip_tos]
                         offset: offsetof(struct na_ip, ip_tos)
                         length: sizeof(ip->ip_tos)], // FIXME, decode TOS bits?
    [NADecodedItem itemWithName: @"ip.tlen"
                          value: [NSNumber numberWithInt: ntohs(ip->ip_len)]
                         offset: offsetof(struct na_ip, ip_len)
                         length: sizeof(ip->ip_len)],
    [NADecodedItem itemWithName: @"ip.id"
                          value: [NSString stringWithFormat: @"0x%04x", ntohs(ip->ip_id)]
                         offset: offsetof(struct na_ip, ip_id)
                         length: sizeof(ip->ip_id)],
    [NADecodedItem itemWithName: @"ip.flags"
                          value: ip_flags
                         offset: offsetof(struct na_ip, ip_ffoff)
                         length: sizeof(ip->ip_ffoff)],
    [NADecodedItem itemWithName: @"ip.foff"
                          value: [NSNumber numberWithInt: IP_FOFF(*ip)]
                         offset: offsetof(struct na_ip, ip_ffoff)
                         length: sizeof(ip->ip_ffoff)],
    [NADecodedItem itemWithName: @"ip.ttl"
                          value: [NSNumber numberWithInt: ip->ip_ttl]
                         offset: offsetof(struct na_ip, ip_ttl)
                         length: sizeof(ip->ip_ttl)],
    [NADecodedItem itemWithName: @"ip.prot"
                          value: [NSString stringWithFormat: @"0x%02x", ip->ip_prot]
                         offset: offsetof(struct na_ip, ip_prot)
                         length: sizeof(ip->ip_prot)],
    [NADecodedItem itemWithName: @"ip.checksum"
                          value: [NSNumber numberWithInt: ip->ip_csum]
                         offset: offsetof(struct na_ip, ip_csum)
                         length: sizeof(ip->ip_csum)],
    [NADecodedItem itemWithName: @"ip.src"
                          value: src
                         offset: offsetof(struct na_ip, ip_src)
                         length: sizeof(ip->ip_src)],
    [NADecodedItem itemWithName: @"ip.dst"
                          value: dst
                         offset: offsetof(struct na_ip, ip_dst)
                         length: sizeof(ip->ip_dst)],
    nil ]; // FIXME
}

- (NSString *) description
{
  return @"Internet Protocol, version 4";
}

@end
