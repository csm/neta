//
//  NAPlugin.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/3/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NAPlugin : NSObject
{
  @private
  Class pluginClass;
  NSString *name;
  NSMutableDictionary *children;
}

- (id) initWithClass: (Class) aClass
                name: (NSString *) aName;
- (void) addChild: (NAPlugin *) aPlugin;
- (NAPlugin *) childForName: (NSString *) aName;
- (id) newInstance;

@end
