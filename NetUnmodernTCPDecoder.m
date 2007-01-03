//
//  NetUnmodernTCPDecoder.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NetUnmodernTCPDecoder.h"


@implementation NetUnmodernTCPDecoder

+ (int) protocolNumber
{
  return kNAInternetProtocolNumberTCP;
}

+ (const NAProtocolID *) identifier
{
  return @"tcp";
}

- (NSArray *) parentProtocols
{
  return [NSArray arrayWithObjects: kNAProtocolIdentityIP,
    kNAProtocolIdentityIPv6, nil];
}

- (NSArray *) decodeData: (NSData *) theData
                  source: (NAInternetAddress *) theSource
             destination: (NAInternetAddress *) theDestination
                 version: (NAInternetAddressType) theVersion
{
  return [NSArray array]; // FIXME
}

- (NSString *) description
{
  return @"Transmission Control Protocol";
}

@end
