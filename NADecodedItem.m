//
//  NADecodedItem.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/5/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NADecodedItem.h"


@implementation NADecodedItem

- (id) initWithName: (NSString *) aName
              value: (id) aValue
{
  if ((self = [super init]) != nil)
  {
    name = [[NSString alloc] initWithString: aName];
    value = aValue;
    if (value != nil)
    {
      [value retain];
    }
  }
  
  return self;
}

+ (NADecodedItem *) itemWithName: (NSString *) aName
                           value: (id) aValue
{
  NADecodedItem *item = [[NADecodedItem alloc] initWithName: aName
                                                      value: aValue];
  if (item != nil)
  {
    [item autorelease];
  }
  return item;
}

- (NSString *) name
{
  return name;
}

- (id) value
{
  return value;
}

- (NSString *) description
{
  return [NSString stringWithFormat: @"%@: %@", name, value];
}

- (void) dealloc
{
  [name release];
  if (value != nil)
  {
    [value release];
  }
  [super dealloc];
}

@end
