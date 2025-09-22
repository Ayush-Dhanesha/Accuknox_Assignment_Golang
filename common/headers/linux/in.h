/* Stub header for VS Code IntelliSense - Internet address definitions */
#ifndef _LINUX_IN_H
#define _LINUX_IN_H

#include <stdint.h>

/* Standard well-defined IP protocols */
enum {
    IPPROTO_IP = 0,      /* Dummy protocol for TCP */
    IPPROTO_ICMP = 1,    /* Internet Control Message Protocol */
    IPPROTO_IGMP = 2,    /* Internet Group Management Protocol */
    IPPROTO_IPIP = 4,    /* IPIP tunnels */
    IPPROTO_TCP = 6,     /* Transmission Control Protocol */
    IPPROTO_EGP = 8,     /* Exterior Gateway Protocol */
    IPPROTO_PUP = 12,    /* PUP protocol */
    IPPROTO_UDP = 17,    /* User Datagram Protocol */
    IPPROTO_IDP = 22,    /* XNS IDP protocol */
    IPPROTO_DCCP = 33,   /* Datagram Congestion Control Protocol */
    IPPROTO_RSVP = 46,   /* RSVP protocol */
    IPPROTO_GRE = 47,    /* Cisco GRE tunnels */
    IPPROTO_IPV6 = 41,   /* IPv6-in-IPv4 tunnelling */
    IPPROTO_ESP = 50,    /* Encapsulation Security Payload protocol */
    IPPROTO_AH = 51,     /* Authentication Header protocol */
    IPPROTO_BEETPH = 94, /* IP option pseudo header for BEET */
    IPPROTO_PIM = 103,   /* Protocol Independent Multicast */
    IPPROTO_COMP = 108,  /* Compression Header protocol */
    IPPROTO_SCTP = 132,  /* Stream Control Transport Protocol */
    IPPROTO_UDPLITE = 136, /* UDP-Lite (RFC 3828) */
    IPPROTO_RAW = 255,   /* Raw IP packets */
    IPPROTO_MAX
};

/* Internet address */
struct in_addr {
    uint32_t s_addr;
};

/* Structure describing an Internet socket address */
struct sockaddr_in {
    uint16_t sin_family;    /* Address family */
    uint16_t sin_port;      /* Port number */
    struct in_addr sin_addr; /* Internet address */
    unsigned char sin_zero[8]; /* Pad to size of struct sockaddr */
};

#define INADDR_ANY          ((uint32_t) 0x00000000)
#define INADDR_BROADCAST    ((uint32_t) 0xffffffff)
#define INADDR_NONE         ((uint32_t) 0xffffffff)
#define INADDR_LOOPBACK     ((uint32_t) 0x7f000001)

#define IN_CLASSA(a)        ((((long int) (a)) & 0x80000000) == 0)
#define IN_CLASSA_NET       0xff000000
#define IN_CLASSA_NSHIFT    24
#define IN_CLASSA_HOST      (0xffffffff & ~IN_CLASSA_NET)
#define IN_CLASSA_MAX       128

#define IN_CLASSB(a)        ((((long int) (a)) & 0xc0000000) == 0x80000000)
#define IN_CLASSB_NET       0xffff0000
#define IN_CLASSB_NSHIFT    16
#define IN_CLASSB_HOST      (0xffffffff & ~IN_CLASSB_NET)
#define IN_CLASSB_MAX       65536

#define IN_CLASSC(a)        ((((long int) (a)) & 0xe0000000) == 0xc0000000)
#define IN_CLASSC_NET       0xffffff00
#define IN_CLASSC_NSHIFT    8
#define IN_CLASSC_HOST      (0xffffffff & ~IN_CLASSC_NET)

#define IN_CLASSD(a)        ((((long int) (a)) & 0xf0000000) == 0xe0000000)
#define IN_MULTICAST(a)     IN_CLASSD(a)

#define IN_EXPERIMENTAL(a)  ((((long int) (a)) & 0xe0000000) == 0xe0000000)
#define IN_BADCLASS(a)      ((((long int) (a)) & 0xf0000000) == 0xf0000000)

#endif /* _LINUX_IN_H */
