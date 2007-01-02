/* NACapturedPacket.h -- a captured packet.
   Copyright (C) 2006, 2007  Casey Marshall <casey.s.marshall@gmail.com>

This file is a part of Network Analyzer.

Network Analyzer is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301  USA  */


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
