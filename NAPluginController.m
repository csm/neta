//
//  NAPluginController.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NAPluginController.h"
#import "NAEthernetDecoder.h"
#import "NAProtocolDecoder.h"
#import "NAInternetProtocolDecoder.h"
#import "NAPlugin.h"

@implementation NAPluginController

static NAPluginController *gController = nil;

+ (NAPluginController *) controller
{
  if (gController == nil)
  {
    gController = [[NAPluginController alloc] init];
  }
  return gController;
}

- (id) init
{
  if ((self = [super init]) != nil)
  {
    NSLog(@"creating a plugin controller");
    plugins = [[NSMutableArray alloc] init];
    NSBundle *appBundle = [NSBundle mainBundle];
    NSMutableArray *searchPaths = [NSMutableArray array];
    [searchPaths addObject: [appBundle builtInPlugInsPath]];
    NSArray *libraries
      = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory,
                                            NSAllDomainsMask - NSSystemDomainMask,
                                            YES);
    NSEnumerator *e = [libraries objectEnumerator];
    NSString *s;
    while ((s = [e nextObject]) != nil)
    {
      [searchPaths addObject: [s stringByAppendingPathComponent:
        @"Application Support/Network Analyzer/PlugIns"]];
    }
    
    NSMutableArray *paths = [NSMutableArray array];
    e = [searchPaths objectEnumerator];
    while ((s = [e nextObject]) != nil)
    {
      NSDirectoryEnumerator *dirEnum;
      NSString *current;
      
      dirEnum = [[NSFileManager defaultManager] enumeratorAtPath: s];
      if (dirEnum != nil)
      {
        while ((current = [dirEnum nextObject]) != nil)
        {
          if ([[current pathExtension] isEqualToString: @"naplugin"])
          {
            [paths addObject: [s stringByAppendingPathComponent: current]];
          }
        }
      }
    }
    
    NSLog(@"paths: %@", paths);
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    e = [paths objectEnumerator];
    while ((s = [e nextObject]) != nil)
    {
      [self loadPluginWithPath: s intoDictionary: d];
    }
    
    e = [[d allValues] objectEnumerator];
    NAPlugin *p;
    while ((p = [e nextObject]) != nil)
    {
      NSArray *parents = [[p pluginClass] parentProtocols];
      if ([parents count] == 0)
      {
        // Root protocol (on top of ethernet); must conform to the private
        // protocol NAEthernetDecoder
        if ([[p pluginClass] conformsToProtocol: @protocol(NAEthernetDecoder)])
        {
          [plugins addObject: p];
        }
      }
      
      NSEnumerator *pe = [parents objectEnumerator];

      NSString *parentName;
      while ((parentName = [pe nextObject]) != nil)
      {
        NAPlugin *parent = [d objectForKey: parentName];
        if (parent != nil)
        {
          [parent addChild: p];
        }
        else
        {
          NSLog(@"WARNING plugin %@ references non-existent parent %@",
                [p name], parent);
        }
      }
    }
    
    NSLog(@"plugin tree: %@", plugins);
  }
  
  return self;
}

- (BOOL) loadPluginWithPath: (NSString *) aPath
             intoDictionary: (NSMutableDictionary *) aDict
{
  NSLog(@"loading bundle %@", aPath);
  NSBundle *bundle = [NSBundle bundleWithPath: aPath];
  if (bundle != nil)
  {
    Class pluginClass = [bundle principalClass];
    if (![pluginClass conformsToProtocol: @protocol(NAProtocolDecoder)])
      return NO;
    const NAProtocolID *ident = [pluginClass identifier];
    NAPlugin *plugin = [[NAPlugin alloc] initWithClass: pluginClass
                                                  name: ident
                                                bundle: bundle];
    if ([aDict objectForKey: ident] == nil)
    {
      [aDict setObject: plugin
                forKey: ident];
    }
    else
    {
      NSLog(@"plugin already registered for %@", ident);
    }
    if ([pluginClass conformsToProtocol: @protocol(NAInternetProtocolDecoder)])
    {
      NSLog(@"class is-a internet protocol decoder for protocol %d",
            [pluginClass protocolNumber]);
    }
    return YES;
  }
  return NO;
}

- (NAPlugin *) pluginForProtocol: (NSString *) aProt
{
  // FIXME, walk tree.
  NSEnumerator *e = [plugins objectEnumerator];
  NAPlugin *p;
  while ((p = [e nextObject]) != nil)
  {
    if ([[p name] isEqualToString: aProt])
    {
      return p;
    }
  }
  return nil;
}

@end
