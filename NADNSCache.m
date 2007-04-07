//
//  NADNS.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/12/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NADNSCache.h"
#import <netdb.h>


@implementation NADNSCache

static NADNSCache *gCache = nil;

+ (NADNSCache *) cache
{
  if (gCache == nil)
  {
    gCache = [[NADNSCache alloc] init];
  }
}

- (id) init
{
  if ((self = [super init]) != nil)
  {
    entries = [[NSMutableDictionary alloc] init];
  }
  return self;
}

- (NSString *) hostForAddress: (NAInternetAddress *) anAddress
{
  NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
#if DEBUG
  NSLog(@"user defaults %@", d);
#endif // DEBUG
  if (![d boolForKey: @"reverseLookup"])
  {
    return nil;
  }

  NSString *host = [entries objectForKey: anAddress];
  if (host == nil)
  {
    struct hostent *he;
    if ([anAddress type] == IPv4)
    {
      he = gethostbyaddr ([anAddress bytes], 4, AF_INET);
    }
    else
    {
      he = gethostbyaddr ([anAddress bytes], 16, AF_INET);
    }
    
    if (he != NULL)
    {
      host = [NSString stringWithCString: he->h_name
                                encoding: NSASCIIStringEncoding];
    }
    
    if (host != nil)
    {
      [entries setObject: host
                  forKey: anAddress];
    }
  }
  return host;
}

@end
