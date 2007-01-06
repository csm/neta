//
//  NAPluginRegistry.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/3/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NAPluginRegistry : NSObject
{
  @private
  NSArray *plugins;
}

+ (NAPluginRegistry *) registry;
- (NSArray *) decoders;

@end
