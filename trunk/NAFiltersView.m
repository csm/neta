//
//  NAFiltersView.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/23/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

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
