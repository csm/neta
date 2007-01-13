/* NACaptureSession.h -- a packet capture session.
   Copyright (C) 2006, 2007  Casey Marshall <casey.s.marshall@gmail.com>

This file is a part of Network Analyzer.

Network Analyzer is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301  USA  */


#import <Cocoa/Cocoa.h>
#import "NANetworkDevice.h"
#import "NACapturedPacket.h"
#import "NADecodedPacket.h"
#import "NAEthernetDecoder.h"
#import "NAPluginController.h"
#import "NAPlugin.h"
#import "NAProtocolDecoder.h"
#import "NADecodedItem.h"

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
  
  NSMutableDictionary *decodedPackets;
  NSMutableDictionary *summaries;
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
- (BOOL) saveToURL: (NSURL *) anUrl error: (NSError **) outError;

- (NADecodedPacketSummary *) summaryAtIndex: (int) index;
- (NADecodedPacket *) decodedPacketAtIndex: (int) index;

@end

@protocol NACaptureSessionCallback

- (void) packetsCaptured: (NACaptureSession *) session;

@end