//
//  NetUnmodernICMPDecoder.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/12/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NetUnmodernICMPDecoder.h"


@implementation NetUnmodernICMPDecoder

+ (const NAProtocolID *) identifier
{
  return @"icmp";
}

+ (NSArray *) parentProtocols
{
  return [NSArray arrayWithObject: kNAProtocolIdentityIP ];
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
  
  
}

- (NSArray *) decode;

- (BOOL) validateChild: (Class) aClass;

- (NSData *) payload;
- (unsigned) headerLength;

+ (BOOL) match: (NSData *) theData;

+ (NSString *) pluginInfo;

@end
