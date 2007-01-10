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
02110-1301  USA

Linking Network Analyzer statically or dynamically with other modules
is making a combined work based on Network Analyzer.  Thus, the terms
and conditions of the GNU General Public License cover the whole
combination.

In addition, as a special exception, the copyright holders of Network
Analyzer give you permission to combine Network Analyzer with free
software programs or libraries that are released under the GNU LGPL
and with independent modules that communicate with Network Analyzer
solely through the NAPlugin.framework interface. You may copy and
distribute such a system following the terms of the GNU GPL for
Network Analyzer and the licenses of the other code concerned, provided
that you include the source code of that other code when and as the
GNU GPL requires distribution of source code.

Note that people who make modified versions of Network Analyzer are not
obligated to grant this special exception for their modified versions;
it is their choice whether to do so.  The GNU General Public License
gives permission to release a modified version without this exception;
this exception also makes it possible to release a modified version
which carries forward this exception.  */


#import <Cocoa/Cocoa.h>


@interface NAUtils : NSObject
{
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

+ (NSString *) toHexString: (char *) theBytes
                    length: (int) theLength
                 separator: (NSString *) aSep;
+ (NSString *) toHexString: (NSData *) theData
                 separator: (NSString *) aSep;

@end
