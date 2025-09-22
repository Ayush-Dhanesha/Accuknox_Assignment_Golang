/* Stub header for VS Code IntelliSense - BPF endian conversions */
#ifndef _BPF_BPF_ENDIAN_H
#define _BPF_BPF_ENDIAN_H

#include <stdint.h>

/* Host to network byte order conversions */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define bpf_htons(x) \
    ((uint16_t)((((uint16_t)(x) & 0xff00) >> 8) | \
                (((uint16_t)(x) & 0x00ff) << 8)))

#define bpf_ntohs(x) \
    ((uint16_t)((((uint16_t)(x) & 0xff00) >> 8) | \
                (((uint16_t)(x) & 0x00ff) << 8)))

#define bpf_htonl(x) \
    ((uint32_t)((((uint32_t)(x) & 0xff000000) >> 24) | \
                (((uint32_t)(x) & 0x00ff0000) >> 8)  | \
                (((uint32_t)(x) & 0x0000ff00) << 8)  | \
                (((uint32_t)(x) & 0x000000ff) << 24)))

#define bpf_ntohl(x) \
    ((uint32_t)((((uint32_t)(x) & 0xff000000) >> 24) | \
                (((uint32_t)(x) & 0x00ff0000) >> 8)  | \
                (((uint32_t)(x) & 0x0000ff00) << 8)  | \
                (((uint32_t)(x) & 0x000000ff) << 24)))

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)

#else
#error "Unknown byte order"
#endif

/* 64-bit conversions */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define bpf_htonll(x) \
    ((uint64_t)((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
                (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
                (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
                (((uint64_t)(x) & 0x000000ff00000000ULL) >> 8)  | \
                (((uint64_t)(x) & 0x00000000ff000000ULL) << 8)  | \
                (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
                (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
                (((uint64_t)(x) & 0x00000000000000ffULL) << 56)))

#define bpf_ntohll(x) bpf_htonll(x)

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define bpf_htonll(x) (x)
#define bpf_ntohll(x) (x)

#endif

/* CPU to little endian */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_cpu_to_le16(x) (x)
#define bpf_cpu_to_le32(x) (x)
#define bpf_cpu_to_le64(x) (x)
#define bpf_le16_to_cpu(x) (x)
#define bpf_le32_to_cpu(x) (x)
#define bpf_le64_to_cpu(x) (x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_cpu_to_le16(x) bpf_htons(x)
#define bpf_cpu_to_le32(x) bpf_htonl(x)
#define bpf_cpu_to_le64(x) bpf_htonll(x)
#define bpf_le16_to_cpu(x) bpf_ntohs(x)
#define bpf_le32_to_cpu(x) bpf_ntohl(x)
#define bpf_le64_to_cpu(x) bpf_ntohll(x)
#endif

/* CPU to big endian */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_cpu_to_be16(x) bpf_htons(x)
#define bpf_cpu_to_be32(x) bpf_htonl(x)
#define bpf_cpu_to_be64(x) bpf_htonll(x)
#define bpf_be16_to_cpu(x) bpf_ntohs(x)
#define bpf_be32_to_cpu(x) bpf_ntohl(x)
#define bpf_be64_to_cpu(x) bpf_ntohll(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_cpu_to_be16(x) (x)
#define bpf_cpu_to_be32(x) (x)
#define bpf_cpu_to_be64(x) (x)
#define bpf_be16_to_cpu(x) (x)
#define bpf_be32_to_cpu(x) (x)
#define bpf_be64_to_cpu(x) (x)
#endif

#endif /* _BPF_BPF_ENDIAN_H */
