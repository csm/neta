//
//  NADecodedItem.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/5/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


// A decoded item, represented as a name/value pair.
@interface NADecodedItem : NSObject
{
  @private
  NSString *name;
  id value;
  unsigned offset;
  unsigned length;
}

// Initialize this item. The name describes the item's contents, and the value
// is the representation of those contents.
//
// In general, the value may be anything. If it is an NSArray, or a instance
// of a subclass, it is assumed that the array contains another list of
// NADecodedItems. Otherwise, the description method will be called on the
// value when displayed.
- (id) initWithName: (NSString *) aName
              value: (id) aValue
             offset: (unsigned) anOffset
             length: (unsigned) aLength;
+ (NADecodedItem *) itemWithName: (NSString *) aName
                           value: (id) aValue
                          offset: (unsigned) anOffset
                          length: (unsigned) aLength;
- (NSString *) name;
- (id) value;
- (unsigned) offset;
- (unsigned) length;

@end
