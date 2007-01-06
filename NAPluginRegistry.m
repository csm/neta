//
//  NAPluginRegistry.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/3/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NAPluginRegistry.h"


@implementation NAPluginRegistry

static NAPluginRegistry *gRegistry;

+ (NAPluginRegistry *) registry
{
  return gRegistry;
}

- (NSArray *) plugins
{
  return [NSArray arrayWithArray: plugins];
}

@end
