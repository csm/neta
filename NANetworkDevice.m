/* NANetworkDevice.h -- a network interface.
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


#import "NANetworkDevice.h"

#import <sys/types.h>
#import <sys/socket.h>
#import <ifaddrs.h>
#import <netinet/in.h>
//#import <pcap.h>

@implementation NANetworkDevice

- (id) initWithName: (NSString *) devName
//        description: (NSString *) aDescription
          addresses: (NSArray *) anArray
{
  if ((self = [super init]) != nil)
  {
    name = [[NSString alloc] initWithString: devName];
//    if (aDescription == nil)
//    {
      description = nil;
//    }
//    else
//    {
//      description = [[NSString alloc] initWithString: aDescription];
//    }
    addresses = [[NSArray alloc] initWithArray: anArray];
  }
  
  return self;
}

/*+ (NSArray *) devices
{
  pcap_if_t *ifaces, *i;
  char errbuf[PCAP_ERRBUF_SIZE];
  
  if (pcap_findalldevs (&ifaces, errbuf) == -1)
  {
    [NSException raise: NAPCAPError format: @"pcap_findalldevs: %s", errbuf];
  }
  
  NSMutableArray *devs = [NSMutableArray array];
  for (i = ifaces; i != NULL; i = i->next)
  {
    NSMutableArray *addresses = [NSMutableArray array];
    pcap_addr_t *j;
    for (j = i->addresses; j != NULL; j = j->next)
    {
      if (j->addr->sa_family == AF_INET)
      {
        [addresses addObject: [NAInternetAddress addressWithType: IPv4
                                                           bytes:
          &(((struct sockaddr_in *) j->addr)->sin_addr.s_addr)]];
      }
      else if (j->addr->sa_family == AF_INET6)
      {
        [addresses addObject: [NAInternetAddress addressWithType: IPv6
                                                           bytes:
          &(((struct sockaddr_in6 *) j->addr)->sin6_addr.s6_addr)]];
      }
    }

    NSString *desc = nil;
    if (i->description != NULL)
    {
      desc = [NSString stringWithCString: i->description
                                encoding: NSISOLatin1StringEncoding];
    }
    NANetworkDevice *dev = [[NANetworkDevice alloc]
      initWithName: [NSString stringWithCString: i->name
                                       encoding: NSISOLatin1StringEncoding]
       description: desc
         addresses: addresses];
    [devs addObject: [dev autorelease]];
  }
  
  return [NSArray arrayWithArray: devs];
}*/

+ (NSArray *) devices
{
  struct ifaddrs *ifap, *i;

  if (getifaddrs (&ifap) != 0)
  {
    [NSException raise: NASystemError format: @"getifaddrs failed: %s",
      strerror (errno)];
  }

  NSMutableDictionary *d = [NSMutableDictionary dictionary];
  for (i = ifap; i != NULL; i = i->ifa_next)
  {
    NSString *name = [NSString stringWithCString: i->ifa_name
                                        encoding: NSASCIIStringEncoding];
    NSMutableArray *addrs = [d objectForKey: name];
    if (addrs == nil)
    {
      addrs = [NSMutableArray array];
      [d setObject: addrs forKey: name];
    }
    
    if (i->ifa_addr != NULL)
    {
      if (i->ifa_addr->sa_family == AF_INET)
      {
        [addrs addObject:
          [NAInternetAddress addressWithType: IPv4
                                       bytes: (char *) &(((struct sockaddr_in *) (i->ifa_addr))->sin_addr)]];
      }
      else if (i->ifa_addr->sa_family == AF_INET6)
      {
        [addrs addObject:
          [NAInternetAddress addressWithType: IPv6
                                       bytes: (char *) &(((struct sockaddr_in6 *) (i->ifa_addr))->sin6_addr)]];
      }
    }
  }
  freeifaddrs (ifap);
  
  NSMutableArray *a = [NSMutableArray arrayWithCapacity: [d count]];
  NSArray *keys = [d allKeys];
  int k;
  for (k = 0; k < [keys count]; k++)
  {
    NSString *name = [keys objectAtIndex: k];
    NSArray *addrs = [d objectForKey: name];
    NANetworkDevice *dev = [[NANetworkDevice alloc] initWithName: name
                                                       addresses: addrs];
    [dev autorelease];
    [a addObject: dev];
  }
  
  NSLog(@"created devices %@", a);
  
  return [NSArray arrayWithArray: a];
}

- (NSString *) name
{
  return name;
}

- (NSString *) ifDescription
{
  return description;
}

- (NSArray *) addresses
{
  return [NSArray arrayWithArray: addresses];
}

- (BOOL) hasAddress
{
  return [addresses count] > 0;
}

- (BOOL) isLoopback
{
  return [name isEqual: @"lo0"];
}

- (void) dealloc
{
  if (description != nil)
  {
    [description release];
  }
  [name release];
  [addresses release];
  [super dealloc];
}

- (NSString *) description
{
  return [NSString stringWithFormat: @"%@ %@", name, addresses];
}

@end
