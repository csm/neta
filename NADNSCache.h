//
//  NADNS.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/12/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "NAInternetAddress.h"


@interface NADNSCache : NSObject
{
  @private
  NSMutableDictionary *entries;
}

+ (NADNSCache *) cache;

- (NSString *) hostForAddress: (NAInternetAddress *) anAddress;

@end
