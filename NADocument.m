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
    if (![NSBundle loadNibNamed: @"PanelsAndViews" owner: self])
    {
      NSLog (@"loading nib PanelsAndViews failed.");
    }
    else
    {
      NSLog (@"loaded nib panel: %@; progress indicator: %@",
             loadingProgressPanel, loadingProgress);
      [loadingProgressPanel setAlphaValue: 0.9];
    }
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
  NSLog(@"loadingProgressPanel is %@", loadingProgressPanel);
  NSLog(@"mainWindow is %@", mainWindow);
  [NSApp beginSheet: loadingProgressPanel
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
    [[ts mutableString] setString: @""];
  }
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

// NSTableViewDataSource protocol

- (int) numberOfRowsInTableView: (NSTableView *) aTableView
{
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
    return [packet date];
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

@end
