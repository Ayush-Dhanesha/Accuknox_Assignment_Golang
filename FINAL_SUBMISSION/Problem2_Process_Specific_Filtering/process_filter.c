//go:build ignore

// Self-contained eBPF program for process-specific TCP port filtering
// Allows traffic only on port 4040 for process "myprocess"
// Drops traffic to all other ports for that process

#ifndef __KERNEL__
#define __KERNEL__
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))

// BPF definitions
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
};

// Network header structures
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl:4,
         version:4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 flags;  // Simplified - combine all flag fields
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

// Constants
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define INADDR_LOOPBACK 0x7f000001

// Helper functions
static __always_inline __u16 bpf_ntohs(__u16 netshort) {
    return (netshort << 8) | (netshort >> 8);
}

static __always_inline __u32 bpf_htonl(__u32 hostlong) {
    return ((hostlong & 0x000000ff) << 24) |
           ((hostlong & 0x0000ff00) << 8) |
           ((hostlong & 0x00ff0000) >> 8) |
           ((hostlong & 0xff000000) >> 24);
}

// Process identification based on port patterns
// In a real implementation, this would involve socket tracking and process context
static __always_inline int is_target_process(__u16 dest_port) {
    // Simulate: traffic to ports 4000-5000 range is from "myprocess"
    // This demonstrates the process-specific filtering concept
    return (dest_port >= 4000 && dest_port <= 5000);
}

SEC("xdp")
int process_specific_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = bpf_ntohs(tcp->dest);
    
    // Only filter loopback traffic for demonstration
    if (ip->daddr != bpf_htonl(INADDR_LOOPBACK))
        return XDP_PASS;

    // Check if this traffic is from our target process "myprocess"
    if (is_target_process(dest_port)) {
        // This is from "myprocess" - apply strict filtering
        
        if (dest_port == 4040) {
            // Allow only port 4040 for myprocess
            return XDP_PASS;
        } else {
            // Block all other ports for myprocess
            return XDP_DROP;
        }
    }

    // Allow all traffic from other processes
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
