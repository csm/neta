//
//  NetUnmodernIPv6Decoder.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NetUnmodernIPv6Decoder.h"


@implementation NetUnmodernIPv6Decoder

+ (NAProtocolID *) identifier
{
  return kNAProtocolIdentityIPv6;
}

- (NSArray *) decodeData: (NSData *) theData
{
  return [NSArray array]; // FIXME
}

- (NSString *) description
{
  return @"Internet Protocol, version 6";
}

@end
