/*
 *  helper.c
 *  Network Analyzer
 *
 *  Created by C. Scott Marshall on 12/23/06.
 *  Copyright 2006 __MyCompanyName__. All rights reserved.
 *
 */

#include <sys/select.h>
#include <stdio.h>
#include <errno.h>
#include <pcap.h>
#include <syslog.h>
#include <string.h>

#define TMPFILENAME "/tmp/NACapture.XXXXXXXX"

#if DEBUG
#define LOG_LEVEL LOG_NOTICE
#else
#define LOG_LEVEL LOG_DEBUG
#endif /* DEBUG */

/*
 * The helper program used by Network Analyzer to perform the actual
 * capture. This program is executed by the main program with the
 * privilege "sys.openfile.readwrite./dev/bpf" (if those rights are
 * granted), and it will proceed to capture packets using the pcap
 * interface, writing out these packets to a temporary file.
 *
 * This program accepts exactly five arguments:
 *
 *   - The interface to capture, e.g., "en0".
 *   - The snap length.
 *   - "0" or "1", to be promiscuous.
 *   - The number of packets to capture.
 *   - The capture expression.
 *
 * The program will continuously read packets until the specified number
 * of packets to read is reached (unless it is zero or negative; then it
 * will continue to read packets), or until the character "x" is read over
 * standard input. In addition to reading packets, it will also run in a
 * "semi-interactive" mode, accepting simple commands over standard input,
 * and sending replies over standard output. Each command comprises a single
 * line, as does each reply. The commands are:
 *
 *   "n\n"       Return the current number of packets captured.
 *               The reply is another "n", a space, then the number of
 *               packets captured.
 *   "r\n"       Return "r" followed by 0 or 1 if the capture is still
 *               running.
 *   "x\n"       Stop the capture now, regardless of the number of packets
 *               captured so far. The helper program will keep running
 *   "q\n"       Removes the temporary capture file, and exits the helper
 *               program.
 *
 * On startup, the helper program will print one of two replies:
 *
 *   "+ %s\n"    Is printed on successful startup. The remainder of the
 *               line is the path to the temporary capture file.
 *   "- %s\n"    Is printed if startup fails. The remainder of the line is
 *               a message describing the failure.
 */
int
main (int argc, char **argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  char *ifname, *expr;
  int snap, promisc, max;
  pcap_t *pcap;
  pcap_dumper_t *dumper;
  int i = 0, stdin_fileno, tmpfd;
  /* FILE *tmpfile; */
  char tmpname[sizeof TMPFILENAME + 1];
  int capturing = 1;
  int running = 1;
  
  strcpy (tmpname, TMPFILENAME);
  openlog ("CaptureHelper", LOG_PID | LOG_CONS, LOG_USER);

  syslog (LOG_LEVEL, "checking args count");
  if (argc != 6)
  {
    syslog (LOG_LEVEL, "too few arguments: %d", argc);
    printf ("- Too few arguments\n");
    fflush (stdout);
    return 1;
  }
  
  ifname = argv[1];
  snap = atoi (argv[2]);
  if (snap < 64)
  {
    snap = 65535;
  }
  promisc = atoi (argv[3]);
  max = atoi (argv[4]);
  expr = argv[5];
  syslog (LOG_LEVEL, "params are %s %d %d %d %s", ifname, snap, promisc, max,
          expr);
  
  pcap = pcap_open_live (ifname, snap, promisc, 100, errbuf);
  if (pcap == NULL)
  {
    syslog (LOG_LEVEL, "pcap_open_live: %s", errbuf);
    printf ("- %s\n", errbuf);
    fflush (stdout);
    return 1;
  }
  
  if (pcap_setnonblock (pcap, 1, errbuf))
  {
    syslog (LOG_LEVEL, "pcap_setnonblock: %s", errbuf);
    printf ("- %s\n", errbuf);
    fflush (stdout);
    return 1;
  }
  
  if (strlen (expr))
  {
    struct bpf_program filter;
    if (pcap_compile (pcap, &filter, expr, 1, 0xFFFFFFFF) != 0)
    {
      char *e = pcap_geterr (pcap);
      syslog (LOG_LEVEL, "pcap_compile: %s", e);
      printf ("- %s\n", e);
      fflush (stdout);
      return 1;
    }
    if (pcap_setfilter (pcap, &filter) != 0)
    {
      char *e = pcap_geterr (pcap);
      syslog (LOG_LEVEL, "pcap_setfilter: %s", e);
      printf ("- %s\n", e);
      fflush (stdout);
      return 1;
    }
  }
  
  syslog (LOG_LEVEL, "ids: %d %d %d %d", getuid(), geteuid(),
          getgid(), getegid());
  
  tmpfd = mkstemp (tmpname);
  fchown (tmpfd, getuid (), getgid ());
  if (tmpfd == -1)
  {
    syslog (LOG_LEVEL, "mkstemp: %s", strerror (errno));
    printf ("- %s\n", strerror (errno));
    pcap_close (pcap);
    return 1;
  }
  close (tmpfd);
  
  dumper = pcap_dump_open (pcap, tmpname);
  if (dumper == NULL)
  {
    syslog (LOG_LEVEL, "pcap_dump_fopen: %s", pcap_geterr (pcap));
    printf ("- %s\n", pcap_geterr (pcap));
    fflush (stdout);
    return 1;
  }
  
  stdin_fileno = fileno (stdin);
  syslog (LOG_LEVEL, "initialized! telling calling program");
  printf ("+ %s\n", tmpname);
  fflush (stdout);
  
  while (running)
  {
    fd_set inset;
    struct timeval timeo;
    
    if (capturing)
    {
      int n = 10;
    
      if (max > 0 && max - i < n)
        n = max - i;
      n = pcap_dispatch (pcap, n, pcap_dump, (u_char *) dumper);
      if (n < 0)
      {
        capturing = 0;
        pcap_dump_flush (dumper);
        pcap_dump_close (dumper);
        pcap_close (pcap);
      }
      i += n;
      if (max > 0 && i >= max)
      {
        capturing = 0;
        pcap_dump_flush (dumper);
        pcap_dump_close (dumper);
        pcap_close (pcap);
      }
    }
    
    timeo.tv_sec = capturing ? 1 : 10;
    timeo.tv_usec = 0;
    FD_ZERO (&inset);
    FD_SET (stdin_fileno, &inset);
    if (select (stdin_fileno + 1, &inset, NULL, NULL, &timeo) > 0
        && FD_ISSET(stdin_fileno, &inset))
    {
      char c;
      syslog (LOG_LEVEL, "selected stdin!");
      int n = scanf ("%c", &c);
      if (n == EOF)
        break;
      
      switch (c)
      {
        case 'n':
          syslog (LOG_LEVEL, "return count %d", i);
          printf ("n %d\n", i);
          fflush (stdout);
          break;
          
        case 'r':
          syslog (LOG_LEVEL, "return status %d", capturing);
          printf ("r %d\n", capturing);
          fflush (stdout);
          break;
          
        case 'x':
          if (capturing)
          {
            capturing = 0;
            pcap_dump_flush (dumper);
            pcap_dump_close (dumper);
            pcap_close (pcap);
          }
          break;
          
        case 'q':
          if (capturing)
          {
            capturing = 0;
            pcap_dump_flush (dumper);
            pcap_dump_close (dumper);
            pcap_close (pcap);
          }
          running = 0;
          break;
      }
    }
  }
  
  unlink (tmpname);
  return 0;
}
