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
  
  return [NSArray arrayWithObjects:
    [NADecodedItem itemWithName: @"ip.length"
                          value: [NSNumber numberWithInt: len]],
    [NADecodedItem itemWithName: @"ip.checksum"
                          value: [NSNumber numberWithInt: ip->ip_csum]],
    [NADecodedItem itemWithName: @"ip.source"
                          value: src],
    [NADecodedItem itemWithName: @"ip.destination"
                          value: dst],
    nil ]; // FIXME
}

- (NSString *) description
{
  return @"Internet Protocol, version 4";
}

@end
