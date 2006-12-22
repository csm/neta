//
//  NAPCAPFilterViewContainer.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/21/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NAPCAPFilterViewContainer.h"


@implementation NAPCAPFilterViewContainer

- (id) init
{
  if ((self = [super init]) != nil)
  {
    if (![NSBundle loadNibNamed: @"FilterView" owner: self])
    {
      [self release];
      return nil;
    }
  }
  
  return self;
}

@end
