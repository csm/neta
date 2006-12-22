/*
 *  NAProtocols.h
 *  Network Analyzer
 *
 *  Created by C. Scott Marshall on 12/21/06.
 *  Copyright 2006 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdint.h>
#define ETHER_ADDR_LEN 6

#define ETHER_IP   0x0800
#define ETHER_IPv6 0x86DD

typedef struct na_ethernet
{
  uint8_t ether_dst[ETHER_ADDR_LEN];
  uint8_t ether_src[ETHER_ADDR_LEN];
  uint16_t ether_type; 
} na_ethernet;

#define IP_HLEN(ip)    ((((ip).ip_vl) & 0x0f) << 2)
#define IP_VERSION(ip) (((ip).ip_vl) >> 4)

#define IP_OPTIONS_LEN(ip) (IP_HLEN(ip) - 20)
#define IP_OPTIONS(ip) (&(ip) + 20)

#define IP_DATA_LEN(ip) ((ip).ip_len - IP_HLEN(ip))
#define IP_DATA(ip) (&(ip) + IP_HLEN(ip))

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
  /* Follows: options; data. variable-length. */
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
}

#define TCP_DATA_LEN(tcp) ((tcp)
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
  // Follows: options, data. Variable-length.
}
