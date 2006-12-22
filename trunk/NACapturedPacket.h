//
//  NACapturedPacket.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/21/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import <pcap.h>


@interface NACapturedPacket : NSObject
{
  NSDate *date;
  NSData *packet;
  unsigned length;
}

- (id) initWithPacketHeader: (const struct pcap_pkthdr *) theHeader
                packetBytes: (const u_char *) theBytes;

- (NSDate *) date;
- (NSData *) packet;
- (unsigned) length;

@end
