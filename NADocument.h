//
//  NADocument.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/20/06.
//  Copyright __MyCompanyName__ 2006 . All rights reserved.
//


#import <Cocoa/Cocoa.h>
#import "NACaptureSession.h"

@interface NADocument : NSDocument < NACaptureSessionCallback >
{
  IBOutlet NSOutlineView *packetDetail;
  IBOutlet NSTextView *packetHex;
  IBOutlet NSTableView *packetsTable;
  IBOutlet NSTextField *statusLine;
  IBOutlet NSWindow *mainWindow;
  
  IBOutlet NSPanel *loadingProgressPanel;
  IBOutlet NSProgressIndicator *loadingProgress;
  
  NACaptureSession *captureSession;
}

- (void) beginOfflineSheet: (id) arg;
- (void) packetsTableNotify: (NSNotification *) n;

// Toolbars

#define NAToolbarCaptureIdentifier @"NAToolbarCapture"
#define NAToolbarSaveIdentifier    @"NAToolbarSave"
#define NAToolbarSearchIdentifier  @"NAToolbarSearch"

- (void) setupToolbar;
- (NSToolbarItem *) toolbar: (NSToolbar *) toolbar
      itemForItemIdentifier: (NSString *) itemIdentifier
  willBeInsertedIntoToolbar: (BOOL) flag;
- (NSArray *) toolbarAllowedItemIdentifiers: (NSToolbar *) toolbar;
- (NSArray *) toolbarDefaultItemIdentifiers: (NSToolbar *) toolbar;

// NSTableViewDataSource

- (int) numberOfRowsInTableView: (NSTableView *) aTableView;
- (id) tableView: (NSTableView *) aTableView
 objectValueForTableColumn: (NSTableColumn *) aTableColumn
             row: (int) rowIndex;

// NSOutlineViewDataSource

- (id) outlineView: (NSOutlineView *) outlineView
             child: (int) index
            ofItem: (id) item;
- (BOOL) outlineView: (NSOutlineView *) outlineView
    isItemExpandable: (id) item;
- (int) outlineView: (NSOutlineView *) outlineView
 numberOfChildrenOfItem: (id) item;
- (id) outlineView: (NSOutlineView *) outlineView
 objectValueForTableColumn: (NSTableColumn *) tableColumn
            byItem: (id) item;

@end
