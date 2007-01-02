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

- (BOOL) hasAddress;
- (BOOL) isLoopback;

@end
