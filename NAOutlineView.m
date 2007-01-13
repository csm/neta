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
