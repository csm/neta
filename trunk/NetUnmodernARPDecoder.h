//
//  NetUnmodernARPDecoder.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/8/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "NAProtocolDecoder.h"
#import "NAEthernetDecoder.h"


@interface NetUnmodernARPDecoder : NSObject < NAProtocolDecoder, NAEthernetDecoder >
{
  NSData *current;
}

@end
