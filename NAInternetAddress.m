//
//  NAInternetAddress.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/17/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NAInternetAddress.h"
#import "NAConstants.h"

#import <errno.h>
#import <string.h>


@implementation NAInternetAddress

- (id) initWithType: (NAInternetAddressType) aType
              bytes: (char *) theBytes
{
  if ((self = [super init]) != nil)
  {
    type = aType;
    switch (aType)
      {
      case IPv4:
        address = malloc (4);
        if (address == NULL)
          return nil;
        memcpy (address, theBytes, 4);
        break;
      
      case IPv6:
        address = malloc (16);
        if (address == NULL)
          return nil;
        memcpy (address, theBytes, 16);
        break;
      
      default:
        [NSException raise: NSInvalidArgumentException
                format: @"invalid Internet address type (%d)", aType];
      }
  }
  
  return self;
}

+ (NAInternetAddress *) addressWithType: (NAInternetAddressType) aType
                                  bytes: (char *) theBytes
{
  NAInternetAddress *address = [[NAInternetAddress alloc] initWithType: aType
                                                                 bytes: theBytes];
  return [address autorelease];
}

- (NAInternetAddressType) type
{
  return type;
}

- (char *) bytes
{
  char *b;
  int len;

  switch (type)
  {
    case IPv4:
      len = 4;
      break;
      
    case IPv6:
      b = malloc (16);
      if (b = NULL)
      {
        [NSException raise: NASystemError format: @"malloc failed: %s",
          strerror(errno) ];
      }
      memcpy (b, address, 16);
      break;
  }
  
  b = malloc (len);
  if (b == NULL)
  {
    [NSException raise: NASystemError format: @"malloc failed: %s",
      strerror(errno) ];
  }
  memcpy (b, address, len);
  [NSData dataWithBytesNoCopy: b length: len];
  return b;
}

- (void) dealloc
{
  free (address);
  [super dealloc];
}

- (NSString *) description
{
  switch (type)
  {
    case IPv4:
      return [NSString stringWithFormat: @"%d.%d.%d.%d",
        (unsigned) address[0] & 0xFF, (unsigned) address[1] & 0xFF,
        (unsigned) address[2] & 0xFF, (unsigned) address[3] & 0xFF];
      
    case IPv6:
      return [NSString stringWithFormat:
                                 @"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned) address[ 0] & 0xFF, (unsigned) address[ 1] & 0xFF,
        (unsigned) address[ 2] & 0xFF, (unsigned) address[ 3] & 0xFF,
        (unsigned) address[ 4] & 0xFF, (unsigned) address[ 5] & 0xFF,
        (unsigned) address[ 6] & 0xFF, (unsigned) address[ 7] & 0xFF,
        (unsigned) address[ 8] & 0xFF, (unsigned) address[ 9] & 0xFF,
        (unsigned) address[10] & 0xFF, (unsigned) address[11] & 0xFF,
        (unsigned) address[12] & 0xFF, (unsigned) address[13] & 0xFF,
        (unsigned) address[14] & 0xFF, (unsigned) address[15] & 0xFF];
  }
  
  return @""; // NOT REACHED.
}

@end