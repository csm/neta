//
//  NAInternetAddress.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/17/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

typedef enum NAInternetAddressType
{
  IPv4,    // Internet protocol, version 4
  IPv6     // Internet protocol, version 6
} NAInternetAddressType;

@interface NAInternetAddress : NSObject
{
  NAInternetAddressType type;
  char *address;
}

- (id) initWithType: (NAInternetAddressType) aType bytes: (char *) theBytes;

+ (NAInternetAddress *) addressWithType: (NAInternetAddressType) aType
  bytes: (char *) theBytes;

- (NAInternetAddressType) type;
- (char *) bytes;

@end
