//
//  NACaptureSession.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/20/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NACaptureSession.h"
#import "NAConstants.h"

#import <stdio.h>
#import <errno.h>


@implementation NACaptureSession

- (id) initWithDevice: (NANetworkDevice *) aDevice
           snapLength: (unsigned) theSnapLength
          promiscuous: (BOOL) bePromiscuous
                error: (NSError **) outError
{
  if ((self = [super init]) != nil)
  {
    offline = NO;
    finished = NO;
    device = NULL;
    dumper = NULL;
    tmpfiledes = -1;
    tmpfile = NULL;
    strcpy (tmpfilename, "/tmp/NACaptureSession.XXXXXXXX");

    packets = [[NSMutableArray alloc] init];
    if (packets == nil)
    {
      [self release];
      return nil;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';
    captured = 0;
    device = pcap_open_live ([[aDevice name] cStringUsingEncoding: NSISOLatin1StringEncoding],
                             theSnapLength, bePromiscuous, 100,
                             errbuf);
    if (device == NULL)
    {
      NSLog (@"pcap_open_live: %s", errbuf);
      [self release];
      *outError = [[NSError alloc] initWithDomain: NSCocoaErrorDomain
                                             code: NSFileWriteUnknownError
                                         userInfo: nil];
      return nil;
    }
    
    tmpfiledes = mkstemp (tmpfilename);
    if (tmpfiledes == -1)
    {
      NSLog (@"mkstemp: %s", strerror (errno));
      [self release];
      *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                             code: errno
                                         userInfo: nil];
      return nil;
    }
    tmpfile = fdopen (tmpfiledes, "w");
    if (tmpfile == NULL)
    {
      NSLog (@"fdopen: %s", strerror (errno));
      [self release];
      *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                             code: errno
                                         userInfo: nil];
      return nil;
    }
    
    dumper = pcap_dump_fopen (device, tmpfile);
    if (dumper == NULL)
    {
      char *err = pcap_geterr (device);
      NSLog (@"pcap_dumper_fopen: %s", err);
      *outError = [[NSError alloc] initWithDomain: NSCocoaErrorDomain
                                             code: NSFileWriteUnknownError
                                         userInfo: nil];
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
    offline = YES;
    finished = NO;
    device = NULL;
    dumper = NULL;
    tmpfiledes = -1;
    tmpfile = NULL;
    
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
  if (!offline || device == NULL)
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
  return finished;
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
  if (device == NULL)
  {
    return;
  }

  NSLog(@"calling pcap_dispatch...");
  int n = pcap_dispatch (device, 10, session_do_loop, (u_char *) self);
  NSLog(@"pcap_dispatch returned %d", n);
  if (n == 0 && offline)
  {
    finished = YES;
  }
  NSLog(@"finished? %d", finished);
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

- (unsigned) captured
{
  return [packets count];
}

- (NACapturedPacket *) capturedPacketForIndex: (int) index
{
  return [packets objectAtIndex: index];
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
  if (tmpfile != NULL)
  {
    fclose (tmpfile);
    unlink (tmpfilename);
    tmpfiledes = -1;
  }
  if (tmpfiledes != -1)
  {
    close (tmpfiledes);
  }
  [super dealloc];
}

@end
