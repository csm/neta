/* NAController */

#import <Cocoa/Cocoa.h>

@interface NAController : NSObject
{
    IBOutlet id mainWindow;
    IBOutlet id packetDetail;
    IBOutlet id packetHex;
    IBOutlet id packetsTable;
    IBOutlet id statusLabel;
    
    NSToolbar *toolbar;
}

- (void) awakeFromNib;

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
