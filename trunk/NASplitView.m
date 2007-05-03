/* NASidebarOutlineView.m -- "handle-free" split view.
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


#import "NASplitView.h"

@implementation NASplitView

- (void) drawDividerInRect: (NSRect) aRect
{
  static NSColor *background = nil;
  if (background == nil)
  {
    background = [[NSColor colorWithCalibratedRed: 0.914
                                            green: 0.937
                                             blue: 0.98
                                            alpha: 1.0] retain];
  }
  [background set];
  NSRectFill(aRect);
  
  static NSImage *bgImage = nil;
  if (bgImage == nil)
  {
    bgImage = [[NSImage imageNamed: @"button-bg"] retain];
  }
  
  NSSize imgSize = [bgImage size];
  NSRect toDraw;
  toDraw.origin.x = aRect.origin.x;
  toDraw.origin.y = aRect.origin.y + (aRect.size.height - imgSize.height);
  toDraw.size.width = aRect.size.width;
  toDraw.size.height = imgSize.height;

  [bgImage setFlipped: YES];
  [bgImage drawInRect: toDraw
             fromRect: NSZeroRect
            operation: NSCompositeCopy
             fraction: 1.0];
  [bgImage setFlipped: NO];
  
  static NSColor *lineColor = nil;
  if (lineColor == nil)
  {
    lineColor = [[NSColor colorWithCalibratedRed: 0.745
                                           green: 0.745
                                            blue: 0.745
                                           alpha: 1.0] retain];
  }
  [lineColor set];
  aRect.origin.x += aRect.size.width;
  aRect.size.width = 1;
  NSRectFill(aRect);
}

@end
