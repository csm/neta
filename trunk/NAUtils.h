/* NAUtils.h -- utility methods.
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
