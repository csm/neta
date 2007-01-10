//
//  NetUnmodernTCPDecoder.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/2/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "NAAbstractInternetProtocolDecoder.h"


@interface NetUnmodernTCPDecoder : NAAbstractInternetProtocolDecoder
{
  NSData *current;
}

@end
