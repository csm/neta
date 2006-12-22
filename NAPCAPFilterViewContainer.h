//
//  NAPCAPFilterViewContainer.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/21/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "SubviewTableViewController.h"

@interface NAPCAPFilterViewContainer : NSObject
{
  IBOutlet NAPCAPFilterView *view;
  IBOutlet NSPopUpButton *test;
  IBOutlet NSPopUpButton *op;
  IBOutlet NSTextField *value;
  IBOutlet NSButton *add;
  IBOutlet NSButton *remove;
}

@end
