//
//  NANetworkDevice.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/17/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "NAInternetAddress.h"
#import "NAConstants.h"

@interface NANetworkDevice : NSObject
{
  NSString *name;
  NSString *description;
  NSArray *addresses;
}

- (id) initWithName: (NSString *) devName addresses: (NSArray *) anArray;

// Fetch an array of all devices available on the system.
//
// \return An array containing a list of devices on this system. The array
//  will be added to the autorelease pool.
// \throws NASystemError if the list of devices cannot be determined.
+ (NSArray *) devices;

// Fetch the name of this interface.
//
// \return The interface name.
- (NSString *) name;

- (NSString *) ifDescription;

// Return the addresses associated with this interface.
//
// \return A list of NAInternetAddress objects associated with this interface.
- (NSArray *) addresses;

@end
