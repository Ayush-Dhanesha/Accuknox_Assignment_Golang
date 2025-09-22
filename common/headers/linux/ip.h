/* Stub header for VS Code IntelliSense - IP definitions */
#ifndef _LINUX_IP_H
#define _LINUX_IP_H

#include <stdint.h>

#define IPPROTO_IP      0    /* Dummy protocol for TCP */
#define IPPROTO_ICMP    1    /* Internet Control Message Protocol */
#define IPPROTO_IGMP    2    /* Internet Group Management Protocol */
#define IPPROTO_IPIP    4    /* IPIP tunnels */
#define IPPROTO_TCP     6    /* Transmission Control Protocol */
#define IPPROTO_EGP     8    /* Exterior Gateway Protocol */
#define IPPROTO_PUP     12   /* PUP protocol */
#define IPPROTO_UDP     17   /* User Datagram Protocol */
#define IPPROTO_IDP     22   /* XNS IDP protocol */
#define IPPROTO_DCCP    33   /* Datagram Congestion Control Protocol */
#define IPPROTO_RSVP    46   /* RSVP protocol */
#define IPPROTO_GRE     47   /* Cisco GRE tunnels */
#define IPPROTO_IPV6    41   /* IPv6-in-IPv4 tunnelling */
#define IPPROTO_ESP     50   /* Encapsulation Security Payload protocol */
#define IPPROTO_AH      51   /* Authentication Header protocol */
#define IPPROTO_BEETPH  94   /* IP option pseudo header for BEET */
#define IPPROTO_PIM     103  /* Protocol Independent Multicast */
#define IPPROTO_COMP    108  /* Compression Header protocol */
#define IPPROTO_SCTP    132  /* Stream Control Transport Protocol */
#define IPPROTO_UDPLITE 136  /* UDP-Lite (RFC 3828) */
#define IPPROTO_RAW     255  /* Raw IP packets */

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t ihl:4,
            version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint8_t version:4,
            ihl:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#endif /* _LINUX_IP_H */
