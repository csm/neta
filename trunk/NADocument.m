/* NADocument.m -- Network Analyzer document class.
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


#import "NADocument.h"
#import "NAUtils.h"

#import <stdio.h>

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
    NAPCAPFilterViewContainer *c = [[NAPCAPFilterViewContainer alloc] initWithDocument: self];
    [filterPredicates addObject: [c autorelease]];
    [filtersView addSubview: [c view]];
    [c setEnabled: NO];
    [self redoFilterViews];
    plugins = [NAPluginController controller];
    boldOutlineFont = [NSFont fontWithName: @"Helvetica Bold"
                                      size: 11];
    [boldOutlineFont retain];
    outlineKeyStyle = [[NSMutableParagraphStyle alloc] init];
    [outlineKeyStyle setAlignment: NSRightTextAlignment];
    [outlineKeyStyle setLineBreakMode: NSLineBreakByTruncatingTail];
    
    amChangingSelection = NO;
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
  [nc addObserver: self
         selector: @selector(changePacketHexSelection:)
             name: NSTextViewDidChangeSelectionNotification
           object: packetViewHex];
  [nc addObserver: self
         selector: @selector(changePacketHexSelection:)
             name: NSTextViewDidChangeSelectionNotification
           object: packetViewVisible];
  
  [packetViewOffset setVerticallyResizable: YES];
  [packetViewHex setVerticallyResizable: YES];
  [packetViewVisible setVerticallyResizable: YES];
  
  [packetViewOffsetContainer setOuterView: packetHexMainView];
  [packetViewHexContainer setOuterView: packetHexMainView];
  [packetViewVisibleContainer setOuterView: packetHexMainView];
}

- (BOOL) readFromURL: (NSURL *) anUrl
              ofType: (NSString *) aType
               error: (NSError **) outError
{
  if (![anUrl isFileURL])
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
  if (captureSession == nil)
  {
    return NO;
  }
  return [captureSession saveToURL: anUrl
                             error: outError];
}

// Sheets

- (void) beginOfflineSheet: (id) arg
{
#pragma unused(arg)
//  NSLog(@"loadingProgressPanel is %@", loadingProgressPanel);
//  NSLog(@"mainWindow is %@", mainWindow);
  [loadingProgress startAnimation: self];
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
  //NSTextStorage *ts = [packetHex textStorage];
  //int index = [packetsTable selectedRow];
  //if (index >= 0)
  //{
  //  NACapturedPacket *packet = [captureSession capturedPacketForIndex: index];
  //  [[ts mutableString] setString: [NAUtils hexdump: [packet packet]]];
  //}
  //else
  //{
  //  [[ts mutableString] setString: @" "];
  //}

  NSData *packet = nil;
  int index = [packetsTable selectedRow];
  if (index >= 0)
  {
    NACapturedPacket *p = [captureSession capturedPacketForIndex: index];
    packet = [p packet];
  }
  NSTextStorage *offsets = [packetViewOffset textStorage];
  NSTextStorage *hex = [packetViewHex textStorage];
  NSTextStorage *visible = [packetViewVisible textStorage];
  NSMutableString *offsetsString = [offsets mutableString];
  NSMutableString *hexString = [hex mutableString];
  NSMutableString *visibleString = [visible mutableString];
  
  [offsets beginEditing];
  [hex beginEditing];
  [visible beginEditing];
  [offsetsString setString: @" "];
  [hexString setString: @" "];
  [visibleString setString: @" "];
  int lines = 1;
  if (packet != nil)
  {
    lines = 0;
    bool first = true;
    int i;
    for (i = 0; i < [packet length]; i += 16)
    {
      int remain = [packet length] - i;
      NSData *subseq = [packet subdataWithRange:
        NSMakeRange(i, (remain > 16) ? 16 : remain)];
      if (first)
      {
        [offsetsString setString: [NSString stringWithFormat: @"%08x\n", i]];
        [hexString setString: [NAUtils toHexString: subseq
                                         separator: @" "]];
        [hexString appendString: @"\n"];
        [visibleString setString: [NAUtils visibleString: subseq]];
        [visibleString appendString: @"\n"];
      }
      else
      {
        [offsetsString appendString: [NSString stringWithFormat: @"%08x\n", i]];
        [hexString appendString: [NAUtils toHexString: subseq
                                            separator: @" "]];
        [hexString appendString: @"\n"];
        [visibleString appendString: [NAUtils visibleString: subseq]];
        [visibleString appendString: @"\n"];
      }
      first = false;
    }
    
    if (first)
      [offsetsString setString: [NSString stringWithFormat: @"%08x\n",
        [packet length]]];
    else
      [offsetsString appendString: [NSString stringWithFormat: @"%08x\n",
        [packet length]]];
  }
  [offsets endEditing];
  [hex endEditing];
  [visible endEditing];
  
  NSSize minsize = [packetViewOffset minSize];
  minsize.height = 0;
  [packetViewOffset setMinSize: minsize];
  minsize = [packetViewHex minSize];
  minsize.height = 0;
  [packetViewHex setMinSize: minsize];
  minsize = [packetViewVisible minSize];
  minsize.height = 0;
  [packetViewHex setMinSize: minsize];  

  [packetViewOffset sizeToFit];
  [packetViewHex sizeToFit];
  [packetViewVisible sizeToFit];

  NSSize textSize = [packetViewOffset bounds].size;
  NSRect rect = [packetHex frame];
  rect.size.height = textSize.height;
  [packetHex setFrame: rect];
  
  [packetDetail reloadData];
}

- (void) changePacketHexSelection: (NSNotification *) n
{
  if (amChangingSelection)
  {
    return;
  }
  @try
  {
    amChangingSelection = YES;

    // Mapping selected ranges to byte ranges (and back again):
    //  
    // In the hex view, any index i corresponds to selection index i*3,
    // since each byte is represented by either 'XX ', or 'XX\n'.
    //
    // In the visible chars view, any index i corresponds to selection
    // index i+(i/16), since each line of 16 is terminated by a \n.
  
    if ([n object] == packetViewHex)
    {
      NSArray *selected = [packetViewHex selectedRanges];
      NSMutableArray *toSelect = [NSMutableArray array];
      NSEnumerator *e = [selected objectEnumerator];
      id obj;
      while ((obj = [e nextObject]) != nil)
      {
        NSValue *value = obj;
        NSRange range = [value rangeValue];
        NSLog(@"mapping range %d, %d", range.location, range.length);
        unsigned int end = range.location + range.length;
        range.location = (range.location / 3);
        range.location += (range.location / 16);
        end = ((end + 2) / 3);
        end += (end / 16);
        range.length = end - range.location;
        NSLog(@"to range %d, %d", range.location, range.length);
        [toSelect addObject: [NSValue valueWithRange: range]];
      }
      [packetViewVisible setSelectedRanges: toSelect];
    }
    else if ([n object] == packetViewVisible)
    {
      NSArray *selected = [packetViewVisible selectedRanges];
      NSMutableArray *toSelect = [NSMutableArray array];
      NSEnumerator *e = [selected objectEnumerator];
      id obj;
      while ((obj = [e nextObject]) != nil)
      {
        NSValue *value = obj;
        NSRange range = [value rangeValue];
        unsigned int end = range.location + range.length;
        range.location = (range.location - (range.location / 17)) * 3;
        end = (end - (end / 17)) * 3 - 1;
        range.length = end - range.location;
        [toSelect addObject: [NSValue valueWithRange: range]];
      }
      [packetViewHex setSelectedRanges: toSelect];
    }
  }
  @finally
  {
    amChangingSelection = NO;
  }
}

// Actions

- (void) endCaptureFailureConfirm: (NSWindow *) sheet
                       returnCode: (int) returnCode
                      contextInfo: (void *) contextInfo
{
  [NSApp endSheet: capturePanel];
  [capturePanel orderOut: self];
}

- (IBAction) stopCapture: (id) sender
{
  [captureSession stopLiveCapture];
}

- (IBAction) startCapture: (id) sender
{
  NSString *ifname = [[interfaces selectedItem] title];
  int snapLen = 65535;
  if ([snapLengthEnabled state] == NSOnState)
  {
    int i = [snapLength intValue];
    if (i >= 64)
    {
      snapLen = i;
    }
  }
  int maxPackets = -1;
  if ([numPacketsEnabled state] == NSOnState)
  {
    int i = [numPackets intValue];
    if (i > 0)
    {
      maxPackets = i;
    }
  }
  BOOL promisc = [promiscuous state] == NSOnState;
  NSString *op;
  if ([[[allOrAny selectedItem] title] isEqual: @"all"])
  {
    op = @"and ";
  }
  else
  {
    op = @"or ";
  }
  NSMutableString *expr = [NSMutableString string];
  if ([filterEnabled state] == NSOnState)
  {
    int i;
    int n = [filterPredicates count];
    for (i = 0; i < n; i++)
    {
      NAPCAPFilterViewContainer *c = [filterPredicates objectAtIndex: i];
      NSString *p = [c predicate];
      if (p != nil)
      {
        if ([expr length] > 0)
        {
          [expr appendString: op];
        }
        [expr appendString: p];
        [expr appendString: @" "];
      }
    }
  }
       
  AuthorizationRights rights;
  AuthorizationItem item;
  AuthorizationFlags flags = kAuthorizationFlagDefaults | 
    kAuthorizationFlagInteractionAllowed | 
    kAuthorizationFlagExtendRights;
  item.name = "sys.openfile.readwrite./dev/bpf";
  item.valueLength = 0;
  item.value = NULL;
  item.flags = 0;
  rights.count = 1;
  rights.items = &item;

  OSStatus authRet = AuthorizationCreate (NULL, kAuthorizationEmptyEnvironment, 
                                          kAuthorizationFlagDefaults, &pcapAuth);
  if (authRet != 0)
  {
    [NSApp endSheet: capturePanel];
    [capturePanel orderOut: self];
    [captureDevices release];
    NSBeginAlertSheet (nil, nil, nil, nil, mainWindow, self,
                       @selector(endCaptureFailureConfirm:returnCode:contextInfo:),
                       nil, nil,
                       @"Could not authenticate to run capture.");
    return;
  }

  authRet = AuthorizationCopyRights (pcapAuth, &rights,
                                     kAuthorizationEmptyEnvironment,
                                     flags, NULL);
  if (authRet != 0)
  {
    [NSApp endSheet: capturePanel];
    [capturePanel orderOut: self];
    [captureDevices release];
    NSBeginAlertSheet (nil, nil, nil, nil, mainWindow, self,
                       @selector(endCaptureFailureConfirm:returnCode:contextInfo:),
                       nil, nil,
                       @"Could not authenticate to run capture.");
    return;
  }

  NSBundle *bundle = [NSBundle mainBundle];
  NSString *helper = [bundle pathForResource: @"CaptureHelper"
                                      ofType: nil];
  FILE *pipefile;
  char * const args[] = {
    [ifname cStringUsingEncoding: NSISOLatin1StringEncoding],
    [[NSString stringWithFormat: @"%d", snapLen]
      cStringUsingEncoding: NSISOLatin1StringEncoding],
    [[NSString stringWithFormat: @"%d", promisc]
      cStringUsingEncoding: NSISOLatin1StringEncoding],
    [[NSString stringWithFormat: @"%d", maxPackets]
      cStringUsingEncoding: NSISOLatin1StringEncoding],
    [expr cStringUsingEncoding: NSISOLatin1StringEncoding],
    NULL
  };
  
  NSLog (@"running authenticated command %@ %s %s %s %s %s",
         helper, args[0], args[1], args[2], args[3], args[4]);
  
  authRet = AuthorizationExecuteWithPrivileges (pcapAuth,
                                                [helper cStringUsingEncoding:
                                                  NSISOLatin1StringEncoding],
                                                kAuthorizationFlagDefaults,
                                                args, &pipefile);
  if (authRet != 0)
  {
    [NSApp endSheet: capturePanel];
    [capturePanel orderOut: self];
    [captureDevices release];
    NSBeginAlertSheet (nil, nil, nil, nil, mainWindow, self,
                       @selector(endCaptureFailureConfirm:returnCode:contextInfo:),
                       nil, nil,
                       @"Could not authenticate to run capture.");
    return;
  }
  
  captureSession = [[NACaptureSession alloc] initWithPipe: pipefile
                                               maxCapture: maxPackets];

  if (captureSession == nil)
  {
    [NSApp endSheet: capturePanel];
    [capturePanel orderOut: self];
    [captureDevices release];
    NSBeginAlertSheet (nil, nil, nil, nil, mainWindow, self,
                       @selector(endCaptureFailureConfirm:returnCode:contextInfo:),
                       nil, nil,
                       @"Running capture failed.");
    return;
  }
  
  [NSApp endSheet: capturePanel];
  [capturePanel orderOut: self];
  [captureDevices release];
  
  if (maxPackets <= 0)
  {
    [capturingProgress setIndeterminate: YES];
  }
  else
  {
    [capturingProgress setIndeterminate: NO];
    [capturingProgress setMaxValue: maxPackets];
    [capturingProgress setDoubleValue: 0.0];
  }
  [capturingProgress startAnimation: self];
  [capturingNumber setIntValue: 0];
  [NSApp beginSheet: capturingPanel
     modalForWindow: mainWindow
      modalDelegate: nil
     didEndSelector: nil
        contextInfo: nil];

  NSRunLoop *loop = [NSRunLoop currentRunLoop];
  [loop performSelector: @selector(captureLoop:)
                 target: self
               argument: nil
                  order: 1
                  modes: [NSArray arrayWithObjects: NSDefaultRunLoopMode,
                    NSModalPanelRunLoopMode, nil]];
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
      NAPCAPFilterViewContainer *c = [filterPredicates objectAtIndex: i];
      [c setEnabled: NO];
      [c setCanRemove: NO];
    }
  }
  [self redoFilterViews];
}

// Delegated filter view actions

- (void) redoFilterViews
{
  NSColor *color1 = [NSColor colorWithCalibratedRed: 239.0 / 255.0
                                              green: 247.0 / 255.0
                                               blue: 1.0
                                              alpha: 1.0];
  NSColor *color2 = [NSColor whiteColor];
  
  NSRect viewsFrame = [filtersView bounds];
  [filtersView setNeedsDisplay: YES];
  int i;
  const int n = [filterPredicates count];
  for (i = 0; i < n; i++)
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
    if ([filterEnabled state] == NSOnState)
    {
      [c setCanRemove: n > 1];
    }
    else
    {
      [c setCanRemove: NO];
    }
    [[c view] setFrame: NSMakeRect (1, ((n - 1) * 30) - (i * 30) + 1,
                                    viewsFrame.size.width - 2, 30)];
    [[c view] setNeedsDisplay: YES];
  }
}

- (void) addFilterPredicateAfter: (NAPCAPFilterViewContainer *) aContainer
{
  NSLog(@"addFilterPredicateAfter: %@", aContainer);
  if ([filterPredicates count] >= 15)
  {
    return; // max is 15 lines.
  }
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
  NSView *view = [c view];
  NSRect r = [view frame];
  r.origin.y = -100; // so it won't display
  [view setFrame: r];
  [filtersView addSubview: view];
  NSRect panelFrame = [capturePanel frame];
  panelFrame.size.height += [view bounds].size.height;
  panelFrame.origin.y -= [view bounds].size.height;
  [capturePanel setFrame: panelFrame
                 display: YES
                 animate: YES];

  [self redoFilterViews];
}

- (void) removeFilterPredicate: (NAPCAPFilterViewContainer *) aContainer
{
  NSLog(@"removeFilterPredicate: %@", aContainer);
  NSView *view = [aContainer view];
  [view retain];
  [filterPredicates removeObject: aContainer];
  NSRect panelFrame = [capturePanel frame];
  panelFrame.size.height -= [view bounds].size.height;
  panelFrame.origin.y += [view bounds].size.height;
  [capturePanel setFrame: panelFrame
                 display: YES
                 animate: YES];
  [view removeFromSuperview];
  [self redoFilterViews];
}

// Live capture loop.

- (void) captureLoop: (id) arg
{
#pragma unused(arg)
  [captureSession loop: self];
  int cap = [captureSession captured];
  [capturingNumber setIntValue: cap];
  if ([captureSession maxCapture] > 0)
  {
    [capturingProgress setDoubleValue: (double) cap];
  }
  else
  {
    [capturingProgress animate: self];
  }
  
  if ([captureSession liveCaptureFinished])
  {
    [NSApp endSheet: capturingPanel];
    [capturingProgress stopAnimation: self];
    [capturingPanel orderOut: self];
    [captureSession loadTempFile];

    [loadingProgress startAnimation: self];
    [NSApp beginSheet: loadingProgressPanel
       modalForWindow: mainWindow
        modalDelegate: nil
       didEndSelector: nil
          contextInfo: nil];
    NSRunLoop *loop = [NSRunLoop currentRunLoop];
    [loop performSelector: @selector(loop:)
                   target: captureSession
                 argument: self
                    order: 1
                    modes: [NSArray arrayWithObjects: NSDefaultRunLoopMode,
                      NSModalPanelRunLoopMode, nil]];
    [self updateChangeCount: NSChangeDone];
    return;
  }
  
  NSRunLoop *loop = [NSRunLoop currentRunLoop];
  [loop performSelector: @selector(captureLoop:)
                 target: self
               argument: nil
                  order: 1
                  modes: [NSArray arrayWithObjects: NSDefaultRunLoopMode,
                    NSModalPanelRunLoopMode, nil]];
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
  NADecodedPacketSummary *summary = [captureSession summaryAtIndex: rowIndex];
  if ([@"number" isEqual: identifier])
  {
    return [NSNumber numberWithInt: rowIndex + 1];
  }
  if ([@"time" isEqual: identifier])
  {
    NSDate *date = [NSDate dateWithTimeIntervalSince1970: [packet seconds]];
    return [date description];
  }
  if ([@"length" isEqual: identifier])
  {
    return [NSNumber numberWithInt: [packet length]];
  }
  if ([@"source" isEqual: identifier])
  {
    return [summary source];
  }
  if ([@"destination" isEqual: identifier])
  {
    return [summary destination];
  }
  if ([@"protocol" isEqual: identifier])
  {
    return [summary protocol];
  }
  if ([@"description" isEqual: identifier])
  {
    return [summary summary];
  }
  return @"XXX";
}

// NSOutlineViewDataSource protocol.

static NSString *
fetch_plugin_id (NSString *key)
{
  NSArray *split = [key componentsSeparatedByString: @"."];
  if ([split count] > 0)
  {
    NSString *ret = [split objectAtIndex: 0];
    if ([ret length] > 0)
    {
      return [split objectAtIndex: 0];
    }
  }
  return key;
}

- (NSString *) localizeProtocolKey: (NSString *) aKey
{
  NSString *prot = fetch_plugin_id(aKey);
  NSBundle *bundle = nil;
  NSString *table = [prot stringByAppendingString: @"ProtocolKeys"];
  if ([prot isEqualToString: @"eth"])
  {
    bundle = [NSBundle mainBundle];
  }
  else
  {
    NAPlugin *plugin = [plugins pluginForProtocol: prot];
    if (plugin != nil)
    {
      bundle = [plugin bundle];
    }
  }
  
#ifdef DEBUG
  NSLog(@"localizing %@ with bundle %@ and table %@", aKey, bundle,
        table);
#endif // DEBUG
  
  if (bundle != nil)
  {
    return [bundle localizedStringForKey: aKey
                                   value: nil
                                   table: table];
  }
  
  return aKey;
}

- (id) outlineView: (NSOutlineView *) outlineView
             child: (int) index
            ofItem: (id) item
{
  if ([packetsTable selectedRow] < 0 || captureSession == nil)
  {
    return nil;
  }
  NADecodedPacket *packet = [captureSession decodedPacketAtIndex:
    [packetsTable selectedRow]];
  if (packet == nil)
  {
    return nil;
  }
  if (item == nil)
  {
    return [[packet layers] objectAtIndex: index];
  }
  
  if (![item isKindOfClass: [NADecodedItem class]]
      || ![[item value] isKindOfClass: [NSArray class]])
  {
    NSLog(@"warning! does not have children: %@", item);
    return nil;
  }
  
  id val = [[item value] objectAtIndex: index];
#if DEBUG
  NSLog(@"outlineView:%@ child: %d ofItem: %@ returns %@", outlineView,
        index, item, val);
#endif // DEBUG
  return [[item value] objectAtIndex: index];
}

- (BOOL) outlineView: (NSOutlineView *) outlineView
    isItemExpandable: (id) item
{
  return [[item value] isKindOfClass: [NSArray class]];
}

- (int) outlineView: (NSOutlineView *) outlineView
 numberOfChildrenOfItem: (id) item
{
  if ([packetsTable selectedRow] < 0 || captureSession == nil)
  {
    return 0;
  }
  NADecodedPacket *packet = [captureSession decodedPacketAtIndex:
    [packetsTable selectedRow]];
  if (packet == nil)
  {
    return 0;
  }
  if (item == nil)
  {
    return [[packet layers] count];
  }
  else if ([item isKindOfClass: [NADecodedItem class]]
           && [[item value] isKindOfClass: [NSArray class]])
  {
    return [[item value] count];
  }
  return 0;
}

- (id) outlineView: (NSOutlineView *) outlineView
 objectValueForTableColumn: (NSTableColumn *) tableColumn
            byItem: (id) item
{
  if ([packetsTable selectedRow] < 0 || captureSession == nil)
  {
    return nil;
  }
  if (![item isKindOfClass: [NADecodedItem class]])
  {
    NSLog(@"warning! invalid item object: %@", item);
    return nil;
  }
  
  if ([[item value] isKindOfClass: [NSArray class]])
  {
    if ([[tableColumn identifier] isEqual: @"Left"])
    {
      return @"";
    }
    else if ([[tableColumn identifier] isEqual: @"Right"])
    {
      NSString *name = [self localizeProtocolKey: [item name]];
      NSAttributedString *as =
        [[NSAttributedString alloc] initWithString: name
                                        attributes: [NSDictionary dictionaryWithObject: boldOutlineFont
                                                                                forKey: NSFontAttributeName]];
      return [as autorelease];
    }
    return @"???";
  }
  else
  {
    if ([[tableColumn identifier] isEqual: @"Left"])
    {
      NSString *name = [self localizeProtocolKey: [item name]];
      NSDictionary *attr = [NSDictionary dictionaryWithObjectsAndKeys:
        boldOutlineFont, NSFontAttributeName, outlineKeyStyle,
        NSParagraphStyleAttributeName, nil];
      NSAttributedString *as =
      [[NSAttributedString alloc] initWithString: name
                                      attributes: attr];
      return [as autorelease];
    }
    else if ([[tableColumn identifier] isEqual: @"Right"])
    {
      id val = [item value];
      if (val == nil)
        return @"";
      return [val description];
    }
    return @"???";
  }
}

// NACaptureSessionCallback protocol.

- (void) packetsCaptured: (NACaptureSession *) session
{
  [loadingProgress setDoubleValue: [session percentThroughSavefile] * 100.0];
  if ([session isFinished])
  {
    NSLog(@"ending sheet %@...", loadingProgressPanel);
    //[NSApp stopModal];
    [loadingProgress stopAnimation: self];
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

// SubviewTableViewControllerDataSourceProtocol

/*- (NSView *) tableView: (NSTableView *) tableView
            viewForRow: (int) row
{
  return [[filterPredicates objectAtIndex: row] view];
}*/

@end
