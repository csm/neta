//
//  NACapturedPacket.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/21/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NACapturedPacket.h"


@implementation NACapturedPacket

- (id) initWithPacketHeader: (const struct pcap_pkthdr *) theHeader
                packetBytes: (const u_char *) theBytes
{
  if ((self = [super init]) != nil)
  {
    seconds = theHeader->ts.tv_sec + (theHeader->ts.tv_usec / 1000000.0);
    packet = [[NSData alloc] initWithBytes: theBytes
                                    length: theHeader->caplen];
    length = theHeader->len;
  }
  
  return self;
}

- (double) seconds
{
  return seconds;
}

- (NSData *) packet
{
  return packet;
}

- (unsigned) length
{
  return length;
}

- (NSString *) description
{
  return [NSString stringWithFormat: @"Capture @ %lf, %d bytes captured, %d on wire.",
    seconds, [packet length], length];
}

- (void) dealloc
{
  [packet release];
  [super dealloc];
}

@end
