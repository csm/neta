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
    date = [[NSDate alloc] initWithTimeInterval: theHeader->ts.tv_sec
                                      sinceDate: [NSDate dateWithTimeIntervalSince1970: 0]];
    packet = [[NSData alloc] initWithBytes: theBytes
                                    length: theHeader->caplen];
    length = theHeader->len;
  }
  
  return self;
}

- (NSDate *) date
{
  return date;
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
  return [NSString stringWithFormat: @"Capture @ %@, %d bytes captured, %d on wire.",
    date, [packet length], length];
}

- (void) dealloc
{
  [date release];
  [packet release];
  [super dealloc];
}

@end
