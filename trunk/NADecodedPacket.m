//
//  NADecodedPacket.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/5/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NADecodedPacket.h"


@implementation NADecodedPacket

- (id) initWithIndex: (int) anIndex
              layers: (NSArray *) theLayers
{
  if ((self = [super init]) != nil)
  {
    index = anIndex;
    /*NSEnumerator *e = [theLayers objectEnumerator];
    id value;
    while ((value = [e nextObject]) != nil)
    {
      if (![[value class] isKindOfClass: [NSArray class]])
      {
        NSLog(@"decoded packed validation failed: not an NSArray");
        return nil;
      }
      if ([value count] & 1 != 0)
      {
        NSLog(@"decoded packet validation failed: not of even length");
        return nil;
      }
      // XXX FIXME further validation.
    }*/
    packetLayers = [[NSArray alloc] initWithArray: theLayers];
  }

  return self;
}

- (int) index
{
  return index;
}

- (NSArray *) layers
{
  return [NSArray arrayWithArray: packetLayers];
}

- (void) dealloc
{
  [packetLayers release];
  [super dealloc];
}

- (NSString *) description
{
  return [NSString stringWithFormat: @"Packet %d", index];
}

@end
