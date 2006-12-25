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

typedef enum
{
  READING_PCAP_FILE,
  RUNNING_HELPER,
  FINISHED_HELPER,
  FINISHED
} NACaptureState;

@interface NACaptureSession : NSObject
{
  @private

  FILE *pipefile;
  pcap_t *device;
  pcap_dumper_t *dumper;
  //int tmpfiledes;
  char tmpfilename[256];
  FILE *tmpfile;
  
  NACaptureState state;
  int captured;
  NSMutableArray *packets;
  BOOL offline;
  BOOL finished;
  int maxCapture;
}

// Initialize for a "live" capture session. The specified device will
// be opened for capture, with the given snap length, and promiscuous
// mode.
/*- (id) initWithDevice: (NSString *) aDevice
           snapLength: (unsigned) theSnapLength
          promiscuous: (BOOL) bePromiscuous
           maxCapture: (int) theMaxCapture
                error: (NSError **) outError;*/

- (id) initWithPipe: (FILE *) aPipe
         maxCapture: (int) maxCapture;

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
- (void) stopLiveCapture;
- (BOOL) liveCaptureFinished;

- (int) maxCapture;
- (unsigned) captured;
- (NACapturedPacket *) capturedPacketForIndex: (int) index;

// Load the temporary capture file, which was written during a live capture.
- (void) loadTempFile;

// Save the capture to the specified URL.
- (void) saveToURL: (NSURL *) anUrl error: (NSError **) outError;

@end

@protocol NACaptureSessionCallback

- (void) packetsCaptured: (NACaptureSession *) session;

@end