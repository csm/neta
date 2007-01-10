#import "NAController.h"
#import "NAProtocolDecoder.h"

@implementation NAController

- (id) init
{
  if ((self = [super init]) != nil)
  {
    pluginController = [NAPluginController controller];
    rootPlugin = [[NAPlugin alloc] initWithClass: [self class]
                                            name: @"eth"
                                          bundle: [NSBundle mainBundle]];
    NSArray *a = [pluginController plugins];
    NSEnumerator *e = [a objectEnumerator];
    NAPlugin *p;
    while ((p = [e nextObject]) != nil)
    {
      [rootPlugin addChild: p];
    }
  }
  
  return self;
}

- (id) outlineView: (NSOutlineView *) outlineView
             child: (int) index
            ofItem: (id) item
{
#ifdef DEBUG
  NSLog(@"outlineView: %@ child: %d ofItem: %@", outlineView, index, item);
#endif // DEBUG
  if (item == nil)
  {
    return rootPlugin;
  }
  NSArray *children = [item children];
  id child = [children objectAtIndex: index];
#ifdef DEBUG
  NSLog(@"return %@", child);
#endif // DEBUG
  return child;
}

- (BOOL) outlineView: (NSOutlineView *) outlineView
    isItemExpandable: (id) item
{
#ifdef DEBUG
  NSLog(@"outlineView: %@ isItemExpandable: %@", outlineView, item);
  NSLog(@"return %d", [[item children] count] > 0);
#endif // DEBUG
  return [[item children] count] > 0;
}

- (int) outlineView: (NSOutlineView *) outlineView
 numberOfChildrenOfItem: (id) item
{
#ifdef DEBUG
  NSLog(@"outlineView: %@ numberOfChildrenOfItem: %@", outlineView, item);
#endif // DEBUG
  if (item == nil)
  {
#ifdef DEBUG
    NSLog(@"returns 1");
#endif // DEBUG
    return 1;
  }
#ifdef DEBUG
  NSLog(@"returns %d", [[item children] count]);
#endif // DEBUG
  return [[item children] count];
}

- (id) outlineView: (NSOutlineView *) outlineView
 objectValueForTableColumn: (NSTableColumn *) tableColumn
            byItem: (id) item
{
#ifdef DEBUG
  NSLog(@"outlineView: %@ objectValueForTableColumn: %@ byItem: %@",
        outlineView, tableColumn, item);
#endif // DEBUG
  if (item == rootPlugin)
  {
    if (tableColumn == left)
    {
#ifdef DEBUG
      NSLog(@"returns 'eth'");
#endif // DEBUG
      return @"eth";
    }
    else
    {
#ifdef DEBUG
      NSLog(@"returns 'Built-in ethernet decoder.'");
#endif // DEBUG
      return @"Built-in ethernet decoder.";
    }
  }
  else
  {
    if (tableColumn == left)
    {
#ifdef DEBUG
      NSLog(@"returns '%@'", [item name]);
#endif // DEBUG
      return [item name];
    }
    else
    {
#ifdef DEBUG
      NSLog(@"returns '%@'", [[item pluginClass] pluginInfo]);
#endif // DEBUG
      return [[item pluginClass] pluginInfo];
    }
  }
  return nil;
}

@end
