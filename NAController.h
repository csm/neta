/* NAController */

#import <Cocoa/Cocoa.h>
#import "NAPluginController.h"

@interface NAController : NSObject
{
  IBOutlet NSOutlineView *plugins;
  IBOutlet NSWindow *pluginsPanel;
  IBOutlet NSTableColumn *left;
  IBOutlet NSTableColumn *right;
  
  NAPluginController *pluginController;
  NAPlugin *rootPlugin;
}

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
