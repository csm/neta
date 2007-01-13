//
//  NADecodedPacketSummary.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/11/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NADecodedPacketSummary.h"


@implementation NADecodedPacketSummary

- (id) initWithSource: (NSString *) aSource
          destination: (NSString *) aDest
             protocol: (NSString *) aProtocol
              summary: (NSString *) aSummary
{
  if ((self = [super init]) != nil)
  {
    source = [[NSString alloc] initWithString: aSource];
    destination = [[NSString alloc] initWithString: aDest];
    protocol = [[NSString alloc] initWithString: aProtocol];
    summary = [[NSString alloc] initWithString: aSummary];
  }
  
  return self;
}

+ (id) summaryWithSource: (NSString *) aSource
             destination: (NSString *) aDest
                protocol: (NSString *) aProtocol
                 summary: (NSString *) aSummary
{
  NADecodedPacketSummary *summary = [[NADecodedPacketSummary alloc]
    initWithSource: aSource
       destination: aDest
          protocol: aProtocol
           summary: aSummary];
  return [summary autorelease];
}

- (NSString *) source
{
  return [NSString stringWithString: source];
}

- (NSString *) destination
{
  return [NSString stringWithString: destination];
}

- (NSString *) protocol
{
  return [NSString stringWithString: protocol];
}

- (NSString *) summary
{
  return [NSString stringWithString: summary];
}

- (NSString *) description
{
  return [NSString stringWithFormat: @"%@ %@ %@ %@",
    source, destination, protocol, summary];
}

- (void) dealloc
{
  [source release];
  [destination release];
  [protocol release];
  [summary release];
  [super dealloc];
}

@end
