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
             offset: (unsigned) anOffset
             length: (unsigned) aLength
{
  if ((self = [super init]) != nil)
  {
    name = [[NSString alloc] initWithString: aName];
    value = aValue;
    if (value != nil)
    {
      [value retain];
    }
    offset = anOffset;
    length = aLength;
  }
  
  return self;
}

+ (NADecodedItem *) itemWithName: (NSString *) aName
                           value: (id) aValue
                          offset: (unsigned) anOffset
                          length: (unsigned) aLength
{
  NADecodedItem *item = [[NADecodedItem alloc] initWithName: aName
                                                      value: aValue
                                                     offset: anOffset
                                                     length: aLength];
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
  return [NSString stringWithFormat: @"%@(%u,%u): %@", name, offset, length,
    value];
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
