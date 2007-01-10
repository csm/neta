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
  NSBundle *pluginBundle;
  Class pluginClass;
  NSString *name;
  NSMutableDictionary *children;
  id instance;
}

- (id) initWithClass: (Class) aClass
                name: (NSString *) aName
              bundle: (NSBundle *) aBundle;
- (void) addChild: (NAPlugin *) aPlugin;
- (Class) pluginClass;
- (NSBundle *) bundle;
- (NSString *) name;
- (NAPlugin *) childForName: (NSString *) aName;
- (NSArray *) children;
- (id) getInstance;

@end
