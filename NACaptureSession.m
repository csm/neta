/* NACaptureSession.m -- a packet capture session.
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


#import "NACaptureSession.h"
#import "NAConstants.h"

#import <stdio.h>
#import <errno.h>


@implementation NACaptureSession

- (id) initWithPipe: (FILE *) aPipe
         maxCapture: (int) theMaxCapture
{
  if ((self = [super init]) != nil)
  {
    maxCapture = theMaxCapture;
    offline = NO;
    finished = NO;
    device = NULL;
    dumper = NULL;
    pipefile = aPipe;
    captured = 0;
    state = RUNNING_HELPER;

    char c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int n = fscanf (pipefile, "%c %[^\n\r]", &c, errbuf);
    if (n == EOF)
    {
      [self release];
      return nil;
    }
    NSLog (@"child message: %c %s", c, errbuf);
    if (c == '-')
    {
      NSLog (@"Helper program returned error: %s", errbuf);
      [self release];
      return nil;
    }
    else if (c == '+')
    {
      strcpy (tmpfilename, errbuf);
    }
    else
    {
      NSLog (@"bad reply %c", c);
      [self release];
      return nil;
    }
    packets = [[NSMutableArray alloc] init];
    if (packets == nil)
    {
      [self release];
      return nil;
    }
  }
  
  return self;
}

- (id) initWithURL: (NSURL *) anUrl
             error: (NSError **) outError
{
  if ((self = [super init]) != nil)
  {
    maxCapture = -1;
    offline = YES;
    finished = NO;
    device = NULL;
    dumper = NULL;
    state = READING_PCAP_FILE;
    
    packets = [[NSMutableArray alloc] init];
    if (packets == nil)
    {
      [self release];
      return nil;
    }

    if (![anUrl isFileURL])
    {
      *outError = [[NSError alloc] initWithDomain: NSURLErrorDomain
                                             code: NSURLErrorBadURL
                                         userInfo: nil];
      [self release];
      return nil;
    }
    
    const char *path = [[anUrl path] cStringUsingEncoding: NSUTF8StringEncoding];
    FILE *savefile = fopen (path, "r");
    if (savefile == NULL)
    {
      *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                             code: errno
                                         userInfo: nil];
      NSLog(@"fopen: %s: %s", path, strerror (errno));
      [self release];
      return nil;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';
    device = pcap_fopen_offline (savefile, errbuf);
    
    if (device == NULL)
    {
      NSLog (@"pcap_open_offline: %s", errbuf);
      [self release];
      return nil;
    }
  }
  
  return self;
}

- (BOOL) isOffline
{
  return offline;
}

- (double) percentThroughSavefile
{
  if (device == NULL)
  {
    return 0.0;
  }
  
  FILE *savefile = pcap_file (device);
  
  long pos = ftell (savefile);
  fseek (savefile, 0L, SEEK_END);
  long len = ftell (savefile);
  fseek (savefile, pos, SEEK_SET);
  return (double) pos / (double) len;
}

- (BOOL) isFinished
{
  return (state == FINISHED);
}

- (void) stopLiveCapture
{
  if (pipefile != NULL)
  {
    fprintf (pipefile, "x\n");
    fflush (pipefile);
  }
}

- (BOOL) liveCaptureFinished
{
  return (state != RUNNING_HELPER);
}

// C-to-ObjC hoop to jump through.
void
session_do_loop (u_char *user, const struct pcap_pkthdr *h,
                 const u_char *bytes)
{
  NACaptureSession *s = (NACaptureSession *) user;
  [s handlePacketHeader: h bytes: bytes];
}

- (void) loop: (id) argument
{
  if (state == RUNNING_HELPER)
  {
    int num;
    fprintf (pipefile, "n\n");
    fflush (pipefile);
    int n = fscanf (pipefile, "n %d", &num);
    if (n > 0)
    {
      captured = num;
    }
    else
    {
      NSLog (@"helper reply scan returned %d (%s)", n, strerror (errno));
      return;
    }
    
    num = 0;
    fprintf (pipefile, "r\n");
    n = fscanf (pipefile, "r %d", &num);
    if (n > 0)
    {
      if (num == 0)
      {
        state = FINISHED_HELPER;
      }
    }
    else
    {
      NSLog (@"helper reply scan returned %d (%s)", n, strerror (errno));
      return;
    }
    return;
  }

  if (device == NULL)
  {
    return;
  }
  
  if (maxCapture > 0 && [packets count] >= maxCapture)
  {
    state = FINISHED;
    [argument packetsCaptured: self];
    return;
  }

  //NSLog(@"calling pcap_dispatch...");
  int n = 10;
  n = pcap_dispatch (device, n, session_do_loop, (u_char *) self);
  //NSLog(@"pcap_dispatch returned %d", n);
  if (n == 0)
  {
    state = FINISHED;
  }
  //NSLog(@"finished? %d", finished);
  if (argument != nil
      && [argument conformsToProtocol: @protocol(NACaptureSessionCallback)])
  {
    [argument packetsCaptured: self];
  }
}

- (void) handlePacketHeader: (const struct pcap_pkthdr *) theHeader
                      bytes: (const u_char *) theBytes
{
  NACapturedPacket *packet =
    [[NACapturedPacket alloc] initWithPacketHeader: theHeader
                                       packetBytes: theBytes];
  [packets addObject: [packet autorelease]];
  if (dumper != NULL)
  {
    pcap_dump ((u_char *) dumper, theHeader, theBytes);
  }
}

- (int) maxCapture
{
  return maxCapture;
}

- (unsigned) captured
{
  if (state == RUNNING_HELPER)
  {
    return captured;
  }
  return [packets count];
}

- (NACapturedPacket *) capturedPacketForIndex: (int) index
{
  return [packets objectAtIndex: index];
}

- (void) loadTempFile
{
  char errbuf[PCAP_ERRBUF_SIZE];
  device = pcap_open_offline (tmpfilename, errbuf);
  if (device == NULL)
  {
    NSLog (@"pcap_open_offline: %s", errbuf);
    return;
  }
  state = READING_PCAP_FILE;
}

- (void) saveToURL: (NSURL *) anUrl
             error: (NSError **) outError
{
  if (![anUrl isFileURL])
  {
    *outError = [[NSError alloc] initWithDomain: NSURLErrorDomain
                                           code: NSURLErrorBadURL
                                       userInfo: nil];
    return;
  }
  
  const char *path = [[anUrl path] cStringUsingEncoding: NSISOLatin1StringEncoding];
  FILE *file = fopen (path, "w");
  if (file == NULL)
  {
    *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                           code: errno
                                       userInfo: nil];
    return;
  }

  pcap_dump_flush (dumper);
  FILE *readtmp = fopen (tmpfilename, "r");
  if (readtmp == NULL)
  {
    *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                           code: errno
                                       userInfo: nil];
    fclose (file);
    return;
  }
  
  char buffer[4096];
  size_t n;
  while ((n = fread (buffer, 1, sizeof (buffer), readtmp)) != 0)
  {
    if (fwrite (buffer, 1, n, file) < n)
    {
      *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                             code: errno
                                         userInfo: nil];
      break;
    }
  }
  if (ferror(readtmp))
  {
    *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                           code: errno
                                       userInfo: nil];
  }
  fflush (file);
  fclose (file);
  fclose (readtmp);
}

- (void) dealloc
{
  [packets release];
  if (dumper != NULL)
  {
    pcap_dump_close (dumper);
  }
  if (device != NULL)
  {
    pcap_close (device);
  }
  [super dealloc];
}

@end
