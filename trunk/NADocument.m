//
//  MyDocument.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/20/06.
//  Copyright __MyCompanyName__ 2006 . All rights reserved.
//

#import "NADocument.h"
#import "NAUtils.h"

@implementation NADocument

- (id) init
{
  if ((self = [super init]) != nil)
  {
    if (![NSBundle loadNibNamed: @"Panels" owner: self])
    {
      NSLog (@"loading nib Panels failed.");
    }
    else
    {
      NSLog (@"loaded nib panel: %@; progress indicator: %@",
             loadingProgressPanel, loadingProgress);
      [loadingProgressPanel setAlphaValue: 0.9];
    }
    filterPredicates = [[NSMutableArray alloc] init];
    filterTableController = [[SubviewTableViewController controllerWithViewColumn: filterTableColumn] 
      retain];
    [filterTableController setDelegate: self];
  }
  return self;
}

- (NSString *) windowNibName
{
  // Override returning the nib file name of the document
  // If you need to use a subclass of NSWindowController or if your
  // document supports multiple NSWindowControllers, you should remove
  // this method and override -makeWindowControllers instead.
  return @"NADocument";
}

- (void) windowControllerDidLoadNib: (NSWindowController *) aController
{
  [super windowControllerDidLoadNib: aController];
  // Add any code here that needs to be executed once the windowController
  // has loaded the document's window.
  
  [self setupToolbar];
  
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc addObserver: self
         selector: @selector(packetsTableNotify:)
             name: NSTableViewSelectionDidChangeNotification
           object: packetsTable];
}

- (BOOL) readFromURL: (NSURL *) anUrl
              ofType: (NSString *) aType
               error: (NSError **) outError
{
  if (![aType isEqual: @"PcapFile"] || ![anUrl isFileURL])
  {
    return NO;
  }

  captureSession = [[NACaptureSession alloc] initWithURL: anUrl error: outError];
  if (captureSession == nil)
  {
    return NO;
  }
  
  NSRunLoop *loop = [NSRunLoop currentRunLoop];
  [loop performSelector: @selector(loop:)
                 target: captureSession
               argument: self
                  order: 1
                  modes: [NSArray arrayWithObjects: NSDefaultRunLoopMode,
                    NSModalPanelRunLoopMode, nil]];
  [loop performSelector: @selector(beginOfflineSheet:)
                 target: self
               argument: nil
                  order: 1
                  modes: [NSArray arrayWithObjects: NSDefaultRunLoopMode,
                    NSModalPanelRunLoopMode, nil]];
  return YES;
}

- (BOOL) writeToURL: (NSURL *) anUrl
             ofType: (NSString *) aType
              error: (NSError **) outError
{
  return NO;
}

// Sheets

- (void) beginOfflineSheet: (id) arg
{
#pragma unused(arg)
//  NSLog(@"loadingProgressPanel is %@", loadingProgressPanel);
//  NSLog(@"mainWindow is %@", mainWindow);
  [NSApp beginSheet: loadingProgressPanel
     modalForWindow: mainWindow
      modalDelegate: nil
     didEndSelector: nil
        contextInfo: nil];  
}

- (void) showCaptureSheet: (id) sender
{
  captureDevices = [NANetworkDevice devices];
  [captureDevices retain];
  [interfaces removeAllItems];
  int i;
  for (i = 0; i < [captureDevices count]; i++)
  {
    NANetworkDevice *d = [captureDevices objectAtIndex: i];
    [interfaces addItemWithTitle: [d name]];
  }
  
  if ([captureDevices count] > 0)
  {
    NANetworkDevice *device = nil;
    for (i = 0; i < [captureDevices count]; i++)
    {
      NANetworkDevice *d = [captureDevices objectAtIndex: i];
      if ([d hasAddress] && ![d isLoopback])
      {
        [interfaces selectItemAtIndex: i];
        device = d;
        break;
      }
      if ([d hasAddress]) // grab loopback if no other suitable address
      {
        [interfaces selectItemAtIndex: i];
        device = d;
      }
    }
    if (device == nil)
    {
      [interfaces selectItemAtIndex: 0];
      device = [captureDevices objectAtIndex: 0];
    }
    NSArray *addrs = [device addresses];
    [interfaceAddress setStringValue: @"Address:"];
    [interfaceAddress6 setStringValue: @"IPv6 Address:"];
    for (i = 0; i < [addrs count]; i++)
    {
      NAInternetAddress *addr = [addrs objectAtIndex: i];
      if ([addr type] == IPv4)
      {
        [interfaceAddress setStringValue: [NSString stringWithFormat:
          @"Address: %@", addr]];
      }
      if ([addr type] == IPv6)
      {
        [interfaceAddress6 setStringValue: [NSString stringWithFormat:
          @"IPv6 Address: %@", addr]];
      }
    }
  }
  [NSApp beginSheet: capturePanel
     modalForWindow: mainWindow
      modalDelegate: nil
     didEndSelector: nil
        contextInfo: nil];
}

// Notifications

- (void) packetsTableNotify: (NSNotification *) n
{
  NSTextStorage *ts = [packetHex textStorage];
  int index = [packetsTable selectedRow];
  if (index >= 0)
  {
    NACapturedPacket *packet = [captureSession capturedPacketForIndex: index];
    [[ts mutableString] setString: [NAUtils hexdump: [packet packet]]];
  }
  else
  {
    [[ts mutableString] setString: @" "];
  }
}

// Actions

- (IBAction) startCapture: (id) sender;
{
  
}

- (IBAction) cancelCaptureSheet: (id) sender
{
  [NSApp endSheet: capturePanel];
  [capturePanel orderOut: self];
  [captureDevices release];
}

- (IBAction) selectInterface: (id) sender
{
  int i = [interfaces indexOfSelectedItem];
  NANetworkDevice *d = [captureDevices objectAtIndex: i];
  NSString *desc = [d ifDescription];
  if (desc != nil)
  {
    [interfaceDescription setStringValue: desc];
  }
  NSArray *addrs = [d addresses];
  i = 0;
  [interfaceAddress setStringValue: @"Address:"];
  [interfaceAddress6 setStringValue: @"IPv6 Address:"];
  for (i = 0; i < [addrs count]; i++)
  {
    NAInternetAddress *addr = [addrs objectAtIndex: i];
    if ([addr type] == IPv4)
    {
      [interfaceAddress setStringValue: [NSString stringWithFormat:
        @"Address: %@", addr]];
    }
    if ([addr type] == IPv6)
    {
      [interfaceAddress6 setStringValue: [NSString stringWithFormat:
        @"IPv6 Address: %@", addr]];
    }
  }
}

- (IBAction) selectSnapLength: (id) sender
{
  if ([snapLengthEnabled state] == NSOnState)
  {
    [snapLength setEnabled: YES];
  }
  else
  {
    [snapLength setStringValue: @""];
    [snapLength setEnabled: NO];
  }
}

- (IBAction) selectMaxPackets: (id) sender
{
  if ([numPacketsEnabled state] == NSOnState)
  {
    [numPackets setEnabled: YES];
  }
  else
  {
    [numPackets setStringValue: @""];
    [numPackets setEnabled: NO];
  }
}

- (IBAction) selectUseFilter: (id) sender
{
  if ([filterEnabled state] == NSOnState)
  {
    [allOrAny setEnabled: YES];
    if ([filterPredicates count] == 0)
    {
      NAPCAPFilterViewContainer *c = [[NAPCAPFilterViewContainer alloc] initWithDocument: self];
      [filterPredicates addObject: [c autorelease]];
      [self colorizeFilterViews];
    }
    
    int i;
    for (i = 0; i < [filterPredicates count]; i++)
    {
      NAPCAPFilterViewContainer *c = [filterPredicates objectAtIndex: i];
      [c setEnabled: YES];
      [c setCanRemove: [filterPredicates count] > 1];
    }
  }
  else
  {
    [allOrAny setEnabled: NO];
    int i;
    for (i = 0; i < [filterPredicates count]; i++)
    {
      [[filterPredicates objectAtIndex: i] setEnabled: NO];
    }
  }
  [filterTableController reloadTableView];
}

// Delegated filter view actions

- (void) colorizeFilterViews
{
  NSColor *color1 = [NSColor colorWithCalibratedRed: 239.0 / 255.0
                                              green: 247.0 / 255.0
                                               blue: 1.0
                                              alpha: 1.0];
  NSColor *color2 = [NSColor whiteColor];
  
  int i;
  for (i = 0; i < [filterPredicates count]; i++)
  {
    NAPCAPFilterViewContainer *c = [filterPredicates objectAtIndex: i];
    if (i & 1)
    {
      [c setBackground: color2];
    }
    else
    {
      [c setBackground: color1];
    }
    [c setCanRemove: [filterPredicates count] > 1];
  }
}

- (void) addFilterPredicateAfter: (NAPCAPFilterViewContainer *) aContainer
{
  int i = [filterPredicates indexOfObject: aContainer];
  NAPCAPFilterViewContainer *c = [[NAPCAPFilterViewContainer alloc] initWithDocument: self];
  if (i > 0)
  {
    [filterPredicates insertObject: [c autorelease] atIndex: i + 1];
  }
  else
  {
    [filterPredicates addObject: [c autorelease]];
  }
  [self colorizeFilterViews];
  [filterTableController reloadTableView];
}

- (void) removeFilterPredicate: (NAPCAPFilterViewContainer *) aContainer
{
  [filterPredicates removeObject: aContainer];
  [self colorizeFilterViews];
  [filterTableController reloadTableView];
}

// Toolbars

- (void) setupToolbar
{
  NSToolbar *toolbar = [[NSToolbar alloc] initWithIdentifier: @"NADocument"];
  [toolbar setAllowsUserCustomization: YES];
  [toolbar setAutosavesConfiguration: YES];
  [toolbar setDelegate: self];
  [mainWindow setToolbar: [toolbar autorelease]];
}

- (NSToolbarItem *) toolbar: (NSToolbar *) toolbar
      itemForItemIdentifier: (NSString *) itemIdentifier
  willBeInsertedIntoToolbar: (BOOL) flag;
{
  NSToolbarItem *item =
    [[NSToolbarItem alloc] initWithItemIdentifier: itemIdentifier];
  if ([itemIdentifier isEqual: NAToolbarCaptureIdentifier])
  {
    [item setLabel: @"Capture"];
    [item setPaletteLabel: @"Capture" ];
    [item setTarget: self];
    [item setAction: @selector(showCaptureSheet:)];
    [item setImage: [NSImage imageNamed: @"ToolbarCapture"]];
    [item setEnabled: YES];
  }
  else if ([itemIdentifier isEqual: NAToolbarSaveIdentifier])
  {
    [item setLabel: @"Save"];
    [item setPaletteLabel: @"Save"];
  }
  
  return [item autorelease];
}

- (NSArray *) toolbarAllowedItemIdentifiers: (NSToolbar *) toolbar
{
  return [NSArray arrayWithObjects: NSToolbarSeparatorItemIdentifier,
    NSToolbarSpaceItemIdentifier,
    NSToolbarFlexibleSpaceItemIdentifier,
    NSToolbarCustomizeToolbarItemIdentifier,
    NAToolbarCaptureIdentifier,
    NAToolbarSaveIdentifier, nil ];
}

- (NSArray *) toolbarDefaultItemIdentifiers: (NSToolbar *) toolbar
{
  return [NSArray arrayWithObjects: NAToolbarCaptureIdentifier,
    NAToolbarSaveIdentifier,
    NSToolbarFlexibleSpaceItemIdentifier, nil ];
}

- (BOOL) validateToolbarItem: (NSToolbarItem *) anItem
{
  return YES;
}

// NSTableViewDataSource protocol

- (int) numberOfRowsInTableView: (NSTableView *) aTableView
{
  if (aTableView == filterTable)
  {
    return [filterPredicates count];
  }

  int ret;
  if (captureSession == nil)
  {
    ret = 0;
  }
  else
  {
    ret = [captureSession captured];
  }
  NSLog(@"numberOfRowsInTableView: returning %d", ret);
  return ret;
}

- (id) tableView: (NSTableView *) aTableView
 objectValueForTableColumn: (NSTableColumn *) aTableColumn
             row: (int) rowIndex
{
  if (captureSession == nil)
  {
    return nil;
  }
  id identifier = [aTableColumn identifier];
  NACapturedPacket *packet = [captureSession capturedPacketForIndex: rowIndex];
  if ([@"number" isEqual: identifier])
  {
    return [NSNumber numberWithInt: rowIndex + 1];
  }
  if ([@"time" isEqual: identifier])
  {
    return [NSNumber numberWithDouble: [packet seconds]];
  }
  if ([@"length" isEqual: identifier])
  {
    return [NSNumber numberWithInt: [packet length]];
  }
  if ([@"source" isEqual: identifier])
  {
    return @"?";
  }
  if ([@"destination" isEqual: identifier])
  {
    return @"?";
  }
  if ([@"protocol" isEqual: identifier])
  {
    return @"?";
  }
  if ([@"description" isEqual: identifier])
  {
    return [packet description];
  }
  return @"XXX";
}

// NSOutlineViewDataSource protocol.

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

// NACaptureSessionCallback protocol.

- (void) packetsCaptured: (NACaptureSession *) session
{
  if ([session isOffline])
  {
    [loadingProgress setDoubleValue: [session percentThroughSavefile] * 100.0];
    if ([session isFinished])
    {
      NSLog(@"ending sheet %@...", loadingProgressPanel);
      //[NSApp stopModal];
      [NSApp endSheet: loadingProgressPanel];
      [loadingProgressPanel orderOut: self];
      //[[NSRunLoop currentRunLoop] cancelPerformSelector: @selector(loop:)
      //                                           target: captureSession
      //                                         argument: self];
      [packetsTable reloadData];
    }
    else
    {
      [[NSRunLoop currentRunLoop] performSelector: @selector(loop:)
                                           target: captureSession
                                         argument: self
                                            order: 1
                                            modes: [NSArray arrayWithObjects: NSDefaultRunLoopMode,
                                              NSModalPanelRunLoopMode, nil]];      
    }
  }
}

// SubviewTableViewControllerDataSourceProtocol

- (NSView *) tableView: (NSTableView *) tableView
            viewForRow: (int) row
{
  return [[filterPredicates objectAtIndex: row] view];
}

@end
