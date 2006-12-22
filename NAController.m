#import "NAController.h"

@implementation NAController

- (void) awakeFromNib
{
  toolbar = [[NSToolbar alloc] initWithIdentifier: @"NAMainToolbar"];
  [mainWindow setToolbar: toolbar];
  [statusLabel setStringValue: @"Ready to load or capture"];
  
  
}

- (int) numberOfRowsInTableView: (NSTableView *) aTableView
{
  return 3;
}

- (id) tableView: (NSTableView *) aTableView
 objectValueForTableColumn: (NSTableColumn *) aTableColumn
             row: (int) rowIndex
{
  id identifier = [aTableColumn identifier];
  if ([@"number" isEqual: identifier])
  {
    return [NSNumber numberWithInt: rowIndex + 1];
  }
  if ([@"time" isEqual: identifier])
  {
    return [NSNumber numberWithInt: 1024 * (rowIndex + 1)];
  }
  if ([@"length" isEqual: identifier])
  {
    return [NSNumber numberWithDouble: (rowIndex + 1) * 0.2];
  }
  if ([@"source" isEqual: identifier])
  {
    if (rowIndex & 1)
      return @"10.0.0.1:2104";
    return @"10.0.0.2:80";
  }
  if ([@"destination" isEqual: identifier])
  {
    if (rowIndex & 1)
      return @"10.0.0.2:80";
    return @"10.0.0.1:2104";
  }
  if ([@"protocol" isEqual: identifier])
  {
    return @"TCP";
  }
  if ([@"description" isEqual: identifier])
  {
    return [NSString stringWithFormat: @"Packet number %d", rowIndex];
  }
  return @"XXX";
}

- (id) outlineView: (NSOutlineView *) outlineView
             child: (int) index
            ofItem: (id) item
{
  return nil;
}

- (BOOL) outlineView: (NSOutlineView *) outlineView
    isItemExpandable: (id) item
{
  return NO;
}

- (int) outlineView: (NSOutlineView *) outlineView
 numberOfChildrenOfItem: (id) item
{
  return 0;
}

- (id) outlineView: (NSOutlineView *) outlineView
 objectValueForTableColumn: (NSTableColumn *) tableColumn
            byItem: (id) item
{
  return nil;
}

@end
