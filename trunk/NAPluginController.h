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
  NSMutableArray *plugins;
}

+ (NAPluginController *) controller;
- (BOOL) loadPluginWithPath: (NSString *) aPath;
- (NAPlugin *) pluginForProtocol: (NSString *) aProt;

@end
