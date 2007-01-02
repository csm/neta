/* NAInternetAddress.m -- an internet address.
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
    {
      NSMutableString *s = [NSMutableString string];
      int i;
      for (i = 0; i < 16; i++)
      {
        unsigned x = address[i] & 0xFF;
        if (!(i & 1) || i == 15)
        {
          [s appendFormat: @"%02x", x];
        }
        else
        {
          [s appendFormat: @"%02x:", x];
        }        
      }
      return s;
    }
  }
  
  return @""; // NOT REACHED.
}

@end
