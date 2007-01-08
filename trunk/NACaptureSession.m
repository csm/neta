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
#import "NAProtocols.h"
#import "NADecodedItem.h"

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
    
    decodedPackets = [[NSMutableDictionary alloc] init];
    if (decodedPackets == nil)
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

    decodedPackets = [[NSMutableDictionary alloc] init];
    if (decodedPackets == nil)
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

- (BOOL) saveToURL: (NSURL *) anUrl
             error: (NSError **) outError
{
  if (![anUrl isFileURL])
  {
    *outError = [[NSError alloc] initWithDomain: NSURLErrorDomain
                                           code: NSURLErrorBadURL
                                       userInfo: nil];
    return NO;
  }
  
  const char *path = [[anUrl path] cStringUsingEncoding: NSISOLatin1StringEncoding];
  FILE *file = fopen (path, "w");
  if (file == NULL)
  {
    *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                           code: errno
                                       userInfo: nil];
    return NO;
  }

  pcap_dump_flush (dumper);
  FILE *readtmp = fopen (tmpfilename, "r");
  if (readtmp == NULL)
  {
    *outError = [[NSError alloc] initWithDomain: NSPOSIXErrorDomain
                                           code: errno
                                       userInfo: nil];
    fclose (file);
    return NO;
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
  return YES;
}

static NSString *
eth2str (char *addr)
{
  return [NSString stringWithFormat: @"%02x:%02x:%02x:%02x:%02x:%02x",
    (addr[0] & 0xFF), (addr[1] & 0xFF), (addr[2] & 0xFF),
    (addr[3] & 0xFF), (addr[4] & 0xFF), (addr[5] & 0xFF)];
}

static NSString *
ethertype (uint16_t type)
{
  switch (type)
  {
    case kNAEthernetIPProtocol:
      return @"(IPv4)";
      
    case kNAEthernetARPProtocol:
      return @"(ARP)";
      
    case kNAEthernetIPv6Protocol:
      return @"(IPv6)";
      
    default:
      return @"";
  }
}

- (NADecodedPacket *) decodedPacketAtIndex: (int) index
{
  NADecodedPacket *packet = nil;
  if ((packet = [decodedPackets objectForKey: [NSNumber numberWithInt: index]]) == nil)
  {
    NACapturedPacket *cap = [packets objectAtIndex: index];
    NSMutableArray *dec = [NSMutableArray array];
    NSData *capData = [cap packet];
    na_ethernet *ethernet = (na_ethernet *) [capData bytes];
    NSArray *etherDec = [NSArray arrayWithObjects:
      [NADecodedItem itemWithName: @"eth.dst"
                            value: eth2str(ethernet->ether_dst)
                           offset: 0
                           length: ETHER_ADDR_LEN],
      [NADecodedItem itemWithName: @"eth.src"
                            value: eth2str(ethernet->ether_src)
                           offset: ETHER_ADDR_LEN
                           length: ETHER_ADDR_LEN],
      [NADecodedItem itemWithName: @"eth.type"
                            value: [NSString stringWithFormat: @"0x%04x %@",
                              ntohs(ethernet->ether_type),
                              ethertype(ntohs(ethernet->ether_type))]
                           offset: 2 * ETHER_ADDR_LEN
                           length: sizeof(ethernet->ether_type)],
      [NADecodedItem itemWithName: @"eth.data"
                            value: [NSString stringWithFormat: @"(%d bytes)",
                              [capData length] - ETHER_HEADER_LEN]
                           offset: ETHER_HEADER_LEN
                           length: [capData length] - ETHER_HEADER_LEN],
      nil];
    NADecodedItem *item = [NADecodedItem itemWithName: @"eth"
                                                value: etherDec
                                               offset: 0
                                               length: [capData length]];
    [dec addObject: item];
    
    switch (ntohs(ethernet->ether_type))
    {
      case kNAEthernetIPProtocol:
      {
        NAPlugin *ipplug = [[NAPluginController controller] pluginForProtocol: @"ip"];
        NSLog(@"ipplug = %@", ipplug);
        if (ipplug != nil)
        {
          id d = [ipplug newInstance];
          NSData *ipdata = [NSData dataWithBytes: ethernet->ether_data
                                          length: [capData length] - ETHER_HEADER_LEN];
          NSArray *ipdec = [d decodeData: ipdata];
          if (ipdec != nil)
          {
            item = [NADecodedItem itemWithName: @"ip"
                                         value: ipdec
                                        offset: ETHER_HEADER_LEN
                                        length: [ipdata length]];
            NSLog(@"IPv4 decoded item: %@", item);
            [dec addObject: item];
          }
          [d release];
        }
        break;
      }

      case kNAEthernetIPv6Protocol:
      {
        NAPlugin *ip6plug = [[NAPluginController controller] pluginForProtocol:
          @"ip6" ];
        NSLog(@"ip6plug %@", ip6plug);
        if (ip6plug != nil)
        {
          id d = [ip6plug newInstance];
          NSData *ip6data = [NSData dataWithBytes: ethernet->ether_data
                                          length: [capData length] - ETHER_HEADER_LEN];
          NSArray *ipdec = [d decodeData: ip6data];
          if (ipdec != nil)
          {
            item = [NADecodedItem itemWithName: @"ip6"
                                         value: ipdec
                                        offset: ETHER_HEADER_LEN
                                        length: [ip6data length]];
            NSLog(@"IPv6 decoded item %@", item);
            [dec addObject: item];
          }
          [d release];
        }
        break;
      }
    }
    NSLog(@"decoded packet layers (%d): %@", index, dec);
    packet = [[NADecodedPacket alloc] initWithIndex: index
                                             layers: dec];
    [decodedPackets setObject: [packet autorelease]
                       forKey: [NSNumber numberWithInt: index]];
  }
  return packet;
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
