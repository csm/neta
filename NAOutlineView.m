/* NAOutlineView.m -- outline view with blue backgrounds.
   Copyright (C) 2007  Casey Marshall <casey.s.marshall@gmail.com>

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


#import "NAOutlineView.h"

@implementation NAOutlineView

- (void) drawBackgroundInClipRect: (NSRect) aRect
{
  [super drawBackgroundInClipRect: aRect];
  
  if ([self numberOfRows] < 2)
  {
    return;
  }

  NSColor *c1 = [NSColor colorWithCalibratedRed: 0.804
                                          green: 0.863
                                           blue: 0.953
                                          alpha: 1.0];
  NSColor *c2 = [NSColor colorWithCalibratedRed: 0.914
                                          green: 0.937
                                           blue: 0.98
                                          alpha: 1.0];
  
  int i;
  int n = [self numberOfRows];
  for (i = 1; i < n; i++)
  {
    NSRect rect = [self rectOfRow: i];
    rect.size.width -= 4;
    rect.origin.x += 4;
    id item = [self itemAtRow: i];
    if ([self isExpandable: item])
    {
      [c2 set];
      NSRectFill(rect);
      NSRect rect2 = rect;
      float indent = [self indentationPerLevel] * [self levelForRow: i];
      rect2.origin.x += indent + 1;
      rect2.size.width -= indent + 1;
      rect2.size.height -= 1;
      [c1 set];
      NSRectFill(rect2);
    }
    else
    {
      [c2 set];
      NSRectFill(rect);
    }

    int j;
    rect.size.width = [self indentationPerLevel] - 1;
    rect.origin.y -= 1;
    [c1 set];
    for (j = 0; j < [self levelForRow: i]; j++)
    {
      rect.origin.x = j * [self indentationPerLevel] + 5;
      NSRectFill(rect);
    }
  }
}

@end
