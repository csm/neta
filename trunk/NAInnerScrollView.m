//
//  NAInnerScrollView.m
//  Network Analyzer
//
//  Created by Casey Marshall on 4/11/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import "NAInnerScrollView.h"


@implementation NAInnerScrollView

- (id) initWithFrame: (NSRect) frameRect
{
  if ((self = [super initWithFrame: frameRect]) != nil)
  {
    outerView = nil;
  }
  return self;
}

- (NSScrollView *) outerView
{
  return outerView;
}

- (void) setOuterView: (NSScrollView *) aView
{
  outerView = aView;
}

- (void) scrollWheel: (NSEvent *) theEvent
{
  if (outerView != nil)
  {
    [outerView scrollWheel: theEvent];
  }
  else
  {
    [super scrollWheel: theEvent];
  }
}

@end
