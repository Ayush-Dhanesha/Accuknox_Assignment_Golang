//go:build ignore

// Self-contained eBPF program for configurable TCP port filtering
// No external header dependencies

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
    __u16 flags;  // Simplified
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

// Constants
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// BPF map definitions
enum bpf_map_type {
    BPF_MAP_TYPE_ARRAY = 2,
};

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Map to store the port to block (configurable at runtime)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port_map SEC(".maps");

// Map to store packet statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);  // 0: total packets, 1: dropped packets
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// BPF helper function declarations
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, void *key, void *value, __u64 flags) = (void *) 2;

// Helper functions
static __always_inline __u16 bpf_ntohs(__u16 netshort) {
    return (netshort << 8) | (netshort >> 8);
}

// Atomic add function
static __always_inline void atomic_add(__u64 *ptr, __u64 val) {
    __sync_fetch_and_add(ptr, val);
}

SEC("xdp")
int tcp_port_filter(struct xdp_md *ctx)
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
    struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Get the configured port to block (default: 4040)
    __u32 key = 0;
    __u16 *blocked_port = bpf_map_lookup_elem(&blocked_port_map, &key);
    __u16 target_port = blocked_port ? *blocked_port : 4040;

    __u16 dest_port = bpf_ntohs(tcp->dest);
    
    // Update total packet counter
    __u64 *total_count = bpf_map_lookup_elem(&stats_map, &key);
    if (total_count)
        atomic_add(total_count, 1);

    // Check if this packet should be dropped
    if (dest_port == target_port) {
        // Update dropped packet counter
        key = 1;
        __u64 *dropped_count = bpf_map_lookup_elem(&stats_map, &key);
        if (dropped_count)
            atomic_add(dropped_count, 1);
        
        return XDP_DROP;  // Block the packet
    }

    return XDP_PASS;  // Allow the packet
}

char _license[] SEC("license") = "GPL";
