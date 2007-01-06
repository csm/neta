//
//  NAPlugin.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/3/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NAPlugin.h"


@implementation NAPlugin

- (id) initWithClass: (Class) aClass
                name: (NSString *) aName
{
  if ((self = [super init]) != nil)
  {
    pluginClass = aClass;
    name = [[NSString alloc] initWithString: aName];
    children = [[NSMutableDictionary alloc] init];
  }
  
  return self;
}

- (Class) pluginClass
{
  return pluginClass;
}

- (NSString *) name
{
  return [NSString stringWithString: name];
}

- (void) addChild: (NAPlugin *) aPlugin
{
  NSString *name = [aPlugin name];
  if ([children objectForKey: name] == nil)
  {
    [children setObject: aPlugin forKey: name];
  }
}

- (NAPlugin *) childForName: (NSString *) aName
{
  return [children objectForKey: aName];
}

- (id) newInstance
{
  return [[pluginClass alloc] init];
}

- (NSString *) description
{
  return [NSString stringWithFormat: @"%@ children: %@", name, children];
}

- (void) dealloc
{
  [name release];
  [children release];
}

@end
