//
//  NADecodedPacket.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/5/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NADecodedPacket : NSObject
{
  // Index of the decoded packet in the capture.
  int index;
  
  // The decoded protocol layers.
  NSArray *packetLayers;
}

- (id) initWithIndex: (int) anIndex
              layers: (NSArray *) theLayers;
- (int) index;
- (NSArray *) layers;

@end
