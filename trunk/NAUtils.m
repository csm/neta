/* NAUtils.m -- utility methods.
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


#import "NAUtils.h"

#import <ctype.h>


@implementation NAUtils

static char
visible_char (unsigned char code)
{
  if (isgraph (code) || code == ' ')
  {
    return (char) code;
  }
  return '.';
}

+ (NSString *) hexdump: (char *) theBytes length: (unsigned) theLength
{
  return [NAUtils hexdump: [NSData dataWithBytes: theBytes length: theLength]];
}

+ (NSString *) hexdump: (NSData *) theData
{
  int size = [theData length];
  size = size + (size * 3); // XXX be more accurate here.
  NSMutableString *str = [NSMutableString stringWithCapacity: size];
  
  const int n = [theData length];
  if (n == 0)
  {
    return @"00000000\n";
  }
  int i;
  const unsigned char *data = (const unsigned char *) [theData bytes];
  for (i = 0; i + 15 < n; i += 16)
  {
    const unsigned char *p = data + i;
    [str appendFormat: @"%08x  %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
      i,
      p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
      p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15],
      visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
      visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
      visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]),
      visible_char(p[ 9]), visible_char(p[10]), visible_char(p[11]),
      visible_char(p[12]), visible_char(p[13]), visible_char(p[14]),
      visible_char(p[15]) ];
  }
  
  if ((n & 15) != 0)
  {
    const unsigned char *p = data + i;
    [str appendFormat: @"%08x  ", i];
    switch (n & 15)
    {
      case 15:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x     %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]),
          visible_char(p[ 9]), visible_char(p[10]), visible_char(p[11]),
          visible_char(p[12]), visible_char(p[13]), visible_char(p[14]) ];
        break;

      case 14:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x        %c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          p[ 8], p[ 9], p[10], p[11], p[12], p[13],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]),
          visible_char(p[ 9]), visible_char(p[10]), visible_char(p[11]),
          visible_char(p[12]), visible_char(p[13]) ];
        break;
        
      case 13:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x           %c%c%c%c%c%c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          p[ 8], p[ 9], p[10], p[11], p[12],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]),
          visible_char(p[ 9]), visible_char(p[10]), visible_char(p[11]),
          visible_char(p[12]) ];
        break;
        
      case 12:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x              %c%c%c%c%c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          p[ 8], p[ 9], p[10], p[11],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]),
          visible_char(p[ 9]), visible_char(p[10]), visible_char(p[11]) ];
        break;
        
      case 11:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x                 %c%c%c%c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          p[ 8], p[ 9], p[10],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]),
          visible_char(p[ 9]), visible_char(p[10]) ];
        break;

      case 10:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x                    %c%c%c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          p[ 8], p[ 9],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]),
          visible_char(p[ 9]) ];
        break;
        
      case  9:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x  %02x                       %c%c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          p[ 8],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]), visible_char(p[ 8]) ];
        break;
        
      case  8:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x %02x                           %c%c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]), visible_char(p[ 7]) ];
        break;
        
      case  7:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x %02x                              %c%c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]),
          visible_char(p[ 6]) ];
        break;
        
      case  6:
        [str appendFormat: @"%02x %02x %02x %02x %02x %02x                                 %c%c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]), visible_char(p[ 5]) ];
        break;
        
      case  5:
        [str appendFormat: @"%02x %02x %02x %02x %02x                                    %c%c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3], p[ 4],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]), visible_char(p[ 4]) ];
        break;
        
      case  4:
        [str appendFormat: @"%02x %02x %02x %02x                                       %c%c%c%c\n",
          p[ 0], p[ 1], p[ 2], p[ 3],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]),
          visible_char(p[ 3]) ];
        break;
        
      case  3:
        [str appendFormat: @"%02x %02x %02x                                          %c%c%c\n",
          p[ 0], p[ 1], p[ 2],
          visible_char(p[ 0]), visible_char(p[ 1]), visible_char(p[ 2]) ];
        break;
        
      case  2:
        [str appendFormat: @"%02x %02x                                             %c%c\n",
          p[ 0], p[ 1],
          visible_char(p[ 0]), visible_char(p[ 1]) ];
        break;        
        
      case  1:
        [str appendFormat: @"%02x                                                %c\n",
          p[ 0], visible_char(p[ 0]) ];
        break;        
    }
  }
  
  [str appendFormat: @"%08x\n", n];
  
  return [NSString stringWithString: str];
}

@end
