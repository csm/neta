#import "NAPCAPFilterView.h"

@implementation NAPCAPFilterView

- (id)initWithFrame:(NSRect)frameRect
{
	if ((self = [super initWithFrame:frameRect]) != nil)
  {
    backgroundColor = [[NSColor whiteColor] retain];
	}
	return self;
}

- (void)drawRect:(NSRect)rect
{
  [backgroundColor set];
  NSRectFill ([self bounds]);
}

- (void) dealloc
{
  [backgroundColor release];
  [super dealloc];
}

@end
