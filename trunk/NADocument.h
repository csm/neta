/* NADocument.h -- Network Analyzer document class.
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
#import <Security/Authorization.h>
#import "NACaptureSession.h"
#import "NAPCAPFilterViewContainer.h"
#import "NAFiltersView.h"
#import "NAPluginController.h"

@interface NADocument : NSDocument < NACaptureSessionCallback, NAFilterCallback >
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
  //IBOutlet NSTableView *filterTable;
  //IBOutlet NSTableColumn *filterTableColumn;
  IBOutlet NSButton *filterEnabled;
  IBOutlet NSButton *cancelButton;
  IBOutlet NSButton *captureButton;
  IBOutlet NAFiltersView *filtersView;
  IBOutlet NSBox *filtersBox;
  IBOutlet NSBox *interfaceBox;

  IBOutlet NSPanel *capturingPanel;
  IBOutlet NSTextField *capturingNumber;
  IBOutlet NSProgressIndicator *capturingProgress;
  IBOutlet NSButton *capturingStop;

  NACaptureSession *captureSession;
  //SubviewTableViewController *filterTableController;
  NSArray *captureDevices;
  NSMutableArray *filterPredicates;
  AuthorizationRef pcapAuth;
  
  NAPluginController *plugins;
  NSFont *boldOutlineFont;
  NSMutableParagraphStyle *outlineKeyStyle;
}

// Actions.

- (IBAction) stopCapture: (id) sender;
- (IBAction) startCapture: (id) sender;
- (IBAction) cancelCaptureSheet: (id) sender;
- (IBAction) selectInterface: (id) sender;
- (IBAction) selectSnapLength: (id) sender;
- (IBAction) selectMaxPackets: (id) sender;
- (IBAction) selectUseFilter: (id) sender;

// Delegated filter view actions.

// Re-calculate the filter views.
- (void) redoFilterViews;

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

// Live capture loop method.
- (void) captureLoop: (id) arg;

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
- (NSString *) localizeProtocolKey: (NSString *) aKey;

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
