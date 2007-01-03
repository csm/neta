//
//  NAPluginController.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NAPluginController : NSObject
{
  @private
  NSMutableArray *plugins;
}

+ (NAPluginController *) controller;
- (BOOL) loadPluginWithPath: (NSString *) aPath;

@end
