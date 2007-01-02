/* NAPCAPFilterViewContainer.h -- owner for filter view.
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


#import <Cocoa/Cocoa.h>
#import "NAPCAPFilterView.h"

@interface NAPCAPFilterViewContainer : NSObject
{
  IBOutlet NAPCAPFilterView *view;
  IBOutlet NSPopUpButton *who;
  IBOutlet NSPopUpButton *test;
  IBOutlet NSPopUpButton *op;
  IBOutlet NSTextField *value;
  IBOutlet NSButton *add;
  IBOutlet NSButton *remove;

  id document;
}

- (IBAction) add: (id) sender;
- (IBAction) remove: (id) sender;

- (id) initWithDocument: (id) aDoc;
- (NSView *) view;

- (void) setBackground: (NSColor *) background;
- (BOOL) isEnabled;
- (void) setEnabled: (BOOL) aBool;
- (void) setCanRemove: (BOOL) aBool;

- (NSString *) predicate;

@end

@protocol NAFilterCallback

- (void) addFilterPredicateAfter: (NAPCAPFilterViewContainer *) aContainer;
- (void) removeFilterPredicate: (NAPCAPFilterViewContainer *) aContainer;

@end
