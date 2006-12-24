//
//  NADocument.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/20/06.
//  Copyright __MyCompanyName__ 2006 . All rights reserved.
//


#import <Cocoa/Cocoa.h>
#import "NACaptureSession.h"
#import "SubviewTableViewController.h"
#import "NAPCAPFilterViewContainer.h"

@interface NADocument : NSDocument < NACaptureSessionCallback, SubviewTableViewControllerDataSourceProtocol, NAFilterCallback >
{
  IBOutlet NSOutlineView *packetDetail;
  IBOutlet NSTextView *packetHex;
  IBOutlet NSTableView *packetsTable;
  IBOutlet NSTextField *statusLine;
  IBOutlet NSWindow *mainWindow;
  
  IBOutlet NSPanel *loadingProgressPanel;
  IBOutlet NSProgressIndicator *loadingProgress;
  
  IBOutlet NSPanel *capturePanel;
  IBOutlet NSPopUpButton *interfaces;
  IBOutlet NSTextField *interfaceDescription;
  IBOutlet NSTextField *interfaceAddress;
  IBOutlet NSTextField *interfaceAddress6;
  IBOutlet NSButton *snapLengthEnabled;
  IBOutlet NSTextField *snapLength;
  IBOutlet NSButton *promiscuous;
  IBOutlet NSButton *numPacketsEnabled;
  IBOutlet NSTextField *numPackets;
  IBOutlet NSPopUpButton *allOrAny;
  IBOutlet NSTableView *filterTable;
  IBOutlet NSTableColumn *filterTableColumn;
  IBOutlet NSButton *filterEnabled;
  IBOutlet NSButton *cancelButton;
  IBOutlet NSButton *captureButton;
  
  NACaptureSession *captureSession;
  SubviewTableViewController *filterTableController;
  NSArray *captureDevices;
  NSMutableArray *filterPredicates;
}

// Actions.

- (IBAction) startCapture: (id) sender;
- (IBAction) cancelCaptureSheet: (id) sender;
- (IBAction) selectInterface: (id) sender;
- (IBAction) selectSnapLength: (id) sender;
- (IBAction) selectMaxPackets: (id) sender;
- (IBAction) selectUseFilter: (id) sender;

// Delegated filter view actions.

// Re-calculate the alternating filter row colors.
- (void) colorizeFilterViews;

// Adds a new filter view, after the specified filter view (or at the end if
// the given filter view is nil or not in the list).
//
// This is called by one of the existing filter containers, in response to
// the "add" button being clicked.
- (void) addFilterPredicateAfter: (NAPCAPFilterViewContainer *) aContainer;

// Remove the specified filter view from the list.
//
// This is called by one of the existing filter containers, in response to
// that view's "remove" button being clicked.
- (void) removeFilterPredicate: (NAPCAPFilterViewContainer *) aContainer;

- (void) beginOfflineSheet: (id) arg;
- (void) packetsTableNotify: (NSNotification *) n;
- (void) showCaptureSheet: (id) sender;

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
- (BOOL) validateToolbarItem: (NSToolbarItem *) anItem;

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
