/* NAPCAPFilterViewContainer.m -- owner for filter view.
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
