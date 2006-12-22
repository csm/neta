//
//  NACaptureSession.h
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/20/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "NANetworkDevice.h"
#import "NACapturedPacket.h"

#import <pcap.h>
#import <stdio.h>

@interface NACaptureSession : NSObject
{
  @private

  unsigned captured;
  pcap_t *device;
  pcap_dumper_t *dumper;
  int tmpfiledes;
  char tmpfilename[256];
  FILE *tmpfile;
  
  NSMutableArray *packets;
  BOOL offline;
  BOOL finished;
}

// Initialize for a "live" capture session. The specified device will
// be opened for capture, with the given snap length, and promiscuous
// mode.
- (id) initWithDevice: (NANetworkDevice *) aDevice
           snapLength: (unsigned) theSnapLength
          promiscuous: (BOOL) bePromiscuous
                error: (NSError **) outError;

// Initialize with a pre-captured file.
- (id) initWithURL: (NSURL *) anUrl
             error: (NSError **) outError;

- (void) handlePacketHeader: (const struct pcap_pkthdr *) theHeader
                      bytes: (const u_char *) theBytes;

// Run loop method.
- (void) loop: (id) argument;

- (BOOL) isOffline;
- (double) percentThroughSavefile;
- (BOOL) isFinished;

- (unsigned) captured;
- (NACapturedPacket *) capturedPacketForIndex: (int) index;

// Save the capture to the specified URL.
- (void) saveToURL: (NSURL *) anUrl error: (NSError **) outError;

@end

@protocol NACaptureSessionCallback

- (void) packetsCaptured: (NACaptureSession *) session;

@end