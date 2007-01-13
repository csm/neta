/* NetUnmodernIPProtocolDecoder.m -- internet protocol decoder.
   Copyright (C) 2007  Casey Marshall <casey.s.marshall@gmail.com>

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


#import "NetUnmodernIPProtocolDecoder.h"
#import "NAProtocols.h"
#import "NAInternetAddress.h"
#import "NAPluginRegistry.h"
#import "NADecodedItem.h"
#import "NAInternetProtocolDecoder.h"


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

- (id) init
{
  if ((self = [super init]) != nil)
  {
    current = nil;
  }

  return self;
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
  na_ip *ip = (na_ip *) [current bytes];
  NSString *src = [NSString stringWithFormat: @"%@",
    [NAInternetAddress addressWithType: IPv4
                                 bytes: &(ip->ip_src)]];
  NSString *dst = [NSString stringWithFormat: @"%@",
    [NAInternetAddress addressWithType: IPv4
                                 bytes: &(ip->ip_dst)]];
  NSString *summary = [NSString stringWithFormat:
    @"Internet Protocol, version 4; source: %@, destination: %@",
    src, dst];
  return [NADecodedPacketSummary summaryWithSource: src
                                       destination: dst
                                          protocol: @"IPv4"
                                           summary: summary];
}

- (NSArray *) decode
{
  na_ip *ip = (na_ip *) [current bytes];
  NAInternetAddress *src = [NAInternetAddress addressWithType: IPv4
                                                        bytes: &(ip->ip_src)];
  NAInternetAddress *dst = [NAInternetAddress addressWithType: IPv4
                                                        bytes: &(ip->ip_dst)];
  int len = [current length] - IP_HLEN(*ip);
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

- (BOOL) validateChild: (Class) aClass
{
  if (current == nil)
  {
    return NO;
  }
  na_ip *ip = (na_ip *) [current bytes];
  if ([aClass conformsToProtocol: @protocol(NAInternetProtocolDecoder)])
  {
    return ip->ip_prot == [aClass protocolNumber];
  }
  return NO;
}

- (NSData *) payload
{
  if (current == nil)
  {
    return nil;
  }

  na_ip *ip = (na_ip *) [current bytes];
  int len = IP_DATA_LEN(*ip);
  if (len > [current length] - IP_HLEN(*ip))
  {
    len = [current length] - IP_HLEN(*ip);
  }
  NSData *ret = [NSData dataWithBytes: IP_GET_DATA(*ip)
                               length: len];
#if DEBUG
  NSLog(@"returning payload data %@ (length is %d)", ret, len);
#endif // DEBUG
  return ret;
}

- (unsigned) headerLength
{
  if (current == nil)
  {
    return 0;
  }
  
  na_ip *ip = (na_ip *) [current bytes];
  return IP_HLEN(*ip);
}

- (NSString *) description
{
  return @"Internet Protocol, version 4";
}

+ (NSString *) pluginInfo
{
  return @"Internet Protocol decoder. Copyright (C) 2006-2007 Casey Marshall";
}

+ (int) etherType
{
  return kNAEthernetIPProtocol;
}

- (NAInternetAddress *) ipSource
{
  if (current == nil)
  {
    return nil;
  }
  na_ip *ip = (na_ip *) [current bytes];
  return [NAInternetAddress addressWithType: IPv4
                                      bytes: &(ip->ip_src)];
}

- (NAInternetAddress *) ipDestination
{
  if (current == nil)
  {
    return nil;
  }
  na_ip *ip = (na_ip *) [current bytes];
  return [NAInternetAddress addressWithType: IPv4
                                      bytes: &(ip->ip_dst)];
}

@end
