//
//  NAPCAPFilterViewContainer.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/21/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

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
