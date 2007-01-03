/* NAProtocols.h -- network protocol structures.
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
02110-1301  USA

Linking Network Analyzer statically or dynamically with other modules
is making a combined work based on Network Analyzer.  Thus, the terms
and conditions of the GNU General Public License cover the whole
combination.

In addition, as a special exception, the copyright holders of Network
Analyzer give you permission to combine Network Analyzer with free
software programs or libraries that are released under the GNU LGPL
and with independent modules that communicate with Network Analyzer
solely through the NAPlugin.framework interface. You may copy and
distribute such a system following the terms of the GNU GPL for
Network Analyzer and the licenses of the other code concerned, provided
that you include the source code of that other code when and as the
GNU GPL requires distribution of source code.

Note that people who make modified versions of Network Analyzer are not
obligated to grant this special exception for their modified versions;
it is their choice whether to do so.  The GNU General Public License
gives permission to release a modified version without this exception;
this exception also makes it possible to release a modified version
which carries forward this exception.  */


#include <stdint.h>
#include <netinet/in.h>
#define ETHER_ADDR_LEN 6

#define ETHER_IP   0x0800
#define ETHER_IPv6 0x86DD

typedef struct na_ethernet
{
  uint8_t ether_dst[ETHER_ADDR_LEN];
  uint8_t ether_src[ETHER_ADDR_LEN];
  uint16_t ether_type;
  char ether_data[1]; // variable-length
} na_ethernet;

#define IP_HLEN(ip)    ((((ip).ip_vl) & 0x0f) << 2)
#define IP_VERSION(ip) (((ip).ip_vl) >> 4)

#define IP_OPTIONS_LEN(ip) (IP_HLEN(ip) - 20)
#define IP_GET_OPTIONS(ip) (&(ip) + 20)

#define IP_DATA_LEN(ip) ((ip).ip_len - IP_HLEN(ip))
#define IP_GET_DATA(ip) (&(ip) + IP_HLEN(ip))

typedef struct na_ip
{
  uint8_t  ip_vl;     /* Version, header length. */
  uint8_t  ip_tos;
  uint16_t ip_len;
  uint16_t ip_id;
  uint16_t ip_ffoff; /* Flags, fragment offset. */
  uint8_t  ip_ttl;
  uint8_t  ip_prot;
  uint16_t ip_csum;
  struct in_addr ip_src;
  struct in_addr ip_dst;
  char ip_options[1]; /* variable-length */
  /* Follows: data, variable-length after variable-length options. */
} na_ip;

#define IP6_VERSION(ip)  ((ip).ip6_vcl >> 28);

typedef struct na_ip6
{
  uint32_t ip6_vcl;  // 4-bit version; 8-bit class; 20-bit label.
  uint16_t ip6_len;  // payload length
  uint8_t  ip6_next;
  uint8_t  ip6_hop;
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
  char ip6_data[1]; /* variable-length */
} na_ip6;

// #define TCP_DATA_LEN(tcp) ((tcp)
#define TCP_DATA_OFFSET(tcp) (((tcp).tcp_doff >> 4) << 2);
#define TCP_DATA(tcp) (&(tcp) + TCP_DATA_OFFSET(tcp))

typedef struct na_tcp
{
  uint16_t tcp_sport;
  uint16_t tcp_dport;
  uint32_t tcp_seq;
  uint32_t tcp_ack;
  uint8_t tcp_doff;
  uint8_t tcp_flags;
  uint16_t tcp_window;
  uint16_t tcp_csum;
  uint16_t tcp_urg;
  char tcp_options[1]; // variable-length
  // Follows: data. Variable-length after variable-length options.
} na_tcp;

typedef struct na_udp
{
  uint16_t udp_sport;
  uint16_t udp_dport;
  uint16_t udp_length;
  uint16_t udp_csum;
  char udp_data[1]; // actually udp_length - 8 bytes.
} na_udp;
 