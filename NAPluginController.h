//
//  NAPluginController.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "NAPlugin.h"

@interface NAPluginController : NSObject
{
  @private
  NSMutableDictionary *pluginsMap;
  NSMutableArray *plugins;
}

+ (NAPluginController *) controller;
- (NAPlugin *) pluginForProtocol: (NSString *) aProt;
- (BOOL) loadPluginWithPath: (NSString *) aPath;
- (NSArray *) plugins;

@end
