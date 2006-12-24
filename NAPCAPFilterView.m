#import "NAPCAPFilterView.h"

@implementation NAPCAPFilterView

- (id) initWithFrame: (NSRect) frameRect
{
	if ((self = [super initWithFrame: frameRect]) != nil)
  {
    backgroundColor = [[NSColor whiteColor] retain];
	}
	return self;
}

- (BOOL) acceptsFirstMouse: (NSEvent *) anEvent
{
  return NO;
}

- (void) drawRect: (NSRect) rect
{
  [backgroundColor set];
  NSRectFill ([self bounds]);
}

- (void) setBackground: (NSColor *) aColor
{
  [backgroundColor release];
  backgroundColor = aColor;
  [aColor retain];
}

- (void) dealloc
{
  [backgroundColor release];
  [super dealloc];
}

@end
