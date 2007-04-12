//
//  NAInnerScrollView.h
//  Network Analyzer
//
//  Created by Casey Marshall on 4/11/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NAInnerScrollView : NSScrollView
{
  NSScrollView *outerView;
}

- (NSScrollView *) outerView;
- (void) setOuterView: (NSScrollView *) outerView;

@end
