//
//  NANetworkDevice.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/17/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NANetworkDevice.h"

#import <netinet/in.h>
#import <pcap.h>

@implementation NANetworkDevice

- (id) initWithName: (NSString *) devName
        description: (NSString *) aDescription
          addresses: (NSArray *) anArray
{
  if ((self = [super init]) != nil)
  {
    name = [[NSString alloc] initWithString: devName];
    if (aDescription == nil)
    {
      description = nil;
    }
    else
    {
      description = [[NSString alloc] initWithString: aDescription];
    }
    addresses = [[NSArray alloc] initWithArray: anArray];
  }
  
  return self;
}

+ (NSArray *) devices
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
}

/*+ (NSArray *) devices
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
  
  return [NSArray arrayWithArray: a];
}*/

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

- (void) dealloc
{
  [name release];
  [addresses release];
  [super dealloc];
}

- (NSString *) description
{
  return [NSString stringWithFormat: @"%@ %@", name, addresses];
}

@end
