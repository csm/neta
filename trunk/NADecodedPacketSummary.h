//
//  NADecodedPacketSummary.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 1/11/07.
//  Copyright 2007 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface NADecodedPacketSummary : NSObject
{
  @private
  NSString *source;
  NSString *destination;
  NSString *protocol;
  NSString *summary;
}

- (id) initWithSource: (NSString *) aSource
          destination: (NSString *) aDest
             protocol: (NSString *) aProtocol
              summary: (NSString *) aSummary;
+ (id) summaryWithSource: (NSString *) aSource
             destination: (NSString *) aDest
                protocol: (NSString *) aProtocol
                 summary: (NSString *) aSummary;

- (NSString *) source;
- (NSString *) destination;
- (NSString *) protocol;
- (NSString *) summary;

@end
