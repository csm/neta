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
    id item = [self itemAtRow: i];
    if ([self isExpandable: item])
    {
      [c2 set];
      NSRectFill(rect);
      float indent = [self indentationPerLevel] * [self levelForRow: i];
      rect.origin.x += indent + 1;
      rect.size.width -= indent + 1;
      [c1 set];
      NSRectFill(rect);
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
      rect.origin.x = j * [self indentationPerLevel] + 1;
      NSRectFill(rect);
    }
  }
}

@end
