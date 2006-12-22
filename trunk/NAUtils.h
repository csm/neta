//
//  NAUtils.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/18/06.
//  Copyright 2006 Casey Marshall. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NAUtils : NSObject {

}

// Format the given bytes like `hexdump -C', that is, print out the
// contents of the given memory formatted with:
//
//   - The offset of the bytes, in hex
//   - Sixteen bytes, individually encoded in hexadecimal
//   - The same sixteen bytes, as printable characters, or '.'
//
// on each line. Each line presents sixteen bytes, except possibly
// the final line.
+ (NSString *) hexdump: (char *) theBytes length: (unsigned) theLength;
+ (NSString *) hexdump: (NSData *) theData;

@end
