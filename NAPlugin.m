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
              bundle: (NSBundle *) aBundle
{
  if ((self = [super init]) != nil)
  {
    pluginClass = aClass;
    name = [[NSString alloc] initWithString: aName];
    children = [[NSMutableDictionary alloc] init];
    pluginBundle = [aBundle retain];
  }
  
  return self;
}

- (Class) pluginClass
{
  return pluginClass;
}

- (NSBundle *) bundle
{
  return pluginBundle;
}

- (NSString *) name
{
  return [NSString stringWithString: name];
}

- (void) addChild: (NAPlugin *) aPlugin
{
  NSString *n = [aPlugin name];
  if ([children objectForKey: n] == nil)
  {
    [children setObject: aPlugin forKey: n];
  }
}

- (NAPlugin *) childForName: (NSString *) aName
{
  return [children objectForKey: aName];
}

- (NSArray *) children
{
  return [children allValues];
}

- (id) getInstance
{
  if (instance == nil)
  {
    instance = [[pluginClass alloc] init];
  }
  return instance;
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
