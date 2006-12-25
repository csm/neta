//
//  NAPCAPFilterViewContainer.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/21/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NAPCAPFilterViewContainer.h"


@implementation NAPCAPFilterViewContainer

// aDoc is of type NADocument.
- (id) initWithDocument: (id) aDoc
{
  if ((self = [super init]) != nil)
  {
    if (![NSBundle loadNibNamed: @"FilterView" owner: self])
    {
      [self release];
      return nil;
    }
    document = aDoc;
  }
  
  return self;
}

- (NSView *) view
{
  return view;
}

- (BOOL) isEnabled
{
  return [test isEnabled];
}

- (void) setEnabled: (BOOL) enabled
{
  [who    setEnabled: enabled];
  [test   setEnabled: enabled];
  [op     setEnabled: enabled];
  [value  setEnabled: enabled];
  [add    setEnabled: enabled];
  [remove setEnabled: enabled];
}

- (void) setBackground: (NSColor *) aColor
{
  [view setBackground: aColor];
}

- (void) setCanRemove: (BOOL) aBool
{
  [remove setEnabled: aBool];
}

- (IBAction) add: (id) sender
{
  [document addFilterPredicateAfter: self];
}

- (IBAction) remove: (id) sender
{
  [document removeFilterPredicate: self];
}

- (NSString *) predicate
{
  NSMutableString *str = [NSMutableString string];
  NSString *x = [[test selectedItem] title];
  if ([x isEqual: @"is not"])
  {
    [str appendString: @"not "];
  }
    
  x = [[who selectedItem] title];
  if ([x isEqual: @"Source"])
  {
    [str appendString: @"src "];
  }
  else if ([x isEqual: @"Destination"])
  {
    [str appendString: @"dst "];
  }
  
  x = [[test selectedItem] title];
  if ([x isEqual: @"Port"])
  {
    [str appendString: @"port "];
  }
  else if ([x isEqual: @""])
  {
    [str appendString: @"host "];
  }
  
  NSMutableString *s = [NSMutableString string];
  [s appendString: [value stringValue]];
  if ([s length] == 0)
  {
    return nil;
  }
  [s replaceOccurrencesOfString: @" "
                     withString: @"\\ "
                        options: 0
                          range: NSMakeRange(0, [s length])];
  [str appendString: s];
  return [NSString stringWithString: str];
}

@end
