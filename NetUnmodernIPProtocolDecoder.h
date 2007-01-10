//
//  NetUnmodernIPProtocolDecoder.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "NAProtocolDecoder.h"
#import "NAEthernetDecoder.h"

@interface NetUnmodernIPProtocolDecoder : NSObject < NAProtocolDecoder, NAEthernetDecoder >
{
  NSData *current;
}

@end
