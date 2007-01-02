/* NAFiltersView.h -- custom view for a filter list.
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


#import "NAFiltersView.h"


@implementation NAFiltersView

- (id) initWithFrame: (NSRect) aFrameRect
{
  if ((self = [super initWithFrame: aFrameRect]) != nil)
  {
    enabled = YES;
  }
  
  return self;
}

- (void) drawRect: (NSRect) aRect;
{
  NSRect frame = [self bounds];
  [[NSColor clearColor] set];
  [NSBezierPath fillRect: frame];
  if (enabled)
  {
    [[NSColor colorWithCalibratedRed: 190.0 / 255.0
                               green: 190.0 / 255.0
                                blue: 190.0 / 255.0
                               alpha: 1.0] set];
    //NSRectFill (frame);
    [NSBezierPath strokeRect: frame];
    [[NSColor colorWithCalibratedRed: 142.0 / 255.0
                               green: 142.0 / 255.0
                                blue: 142.0 / 255.0
                               alpha: 1.0] set];
//    [NSBezierPath fillRect: NSMakeRect (frame.origin.x, frame.origin.y,
//                                        frame.size.width, 1)];
    NSRectFill (NSMakeRect (frame.origin.x, frame.size.height - 1, frame.size.width, 1));
  }
}

- (BOOL) isEnabled
{
  return enabled;
}

- (void) setEnabled: (BOOL) aBool
{
  enabled = aBool;
}

@end
