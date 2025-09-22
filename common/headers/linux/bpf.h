/* Stub header for VS Code IntelliSense - Linux BPF definitions */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <stdint.h>

/* BPF program types */
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
};

/* BPF map types */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
};

/* XDP actions */
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

/* BPF map update flags */
enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
};

/* BPF map definition macros */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Section attribute */
#define SEC(NAME) __attribute__((section(NAME), used))

/* BPF context structures */
struct xdp_md {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
    uint32_t ingress_ifindex;
    uint32_t rx_queue_index;
};

struct __sk_buff {
    uint32_t len;
    uint32_t pkt_type;
    uint32_t mark;
    uint32_t queue_mapping;
    uint32_t protocol;
    uint32_t vlan_present;
    uint32_t vlan_tci;
    uint32_t vlan_proto;
    uint32_t priority;
    uint32_t ingress_ifindex;
    uint32_t ifindex;
    uint32_t tc_index;
    uint32_t cb[5];
    uint32_t hash;
    uint32_t tc_classid;
    uint32_t data;
    uint32_t data_end;
    uint32_t napi_id;
    uint32_t family;
    uint32_t remote_ip4;
    uint32_t local_ip4;
    uint32_t remote_ip6[4];
    uint32_t local_ip6[4];
    uint32_t remote_port;
    uint32_t local_port;
    uint32_t data_meta;
};

struct bpf_sock {
    uint32_t bound_dev_if;
    uint32_t family;
    uint32_t type;
    uint32_t protocol;
    uint32_t mark;
    uint32_t priority;
    uint32_t src_ip4;
    uint32_t src_ip6[4];
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t dst_ip4;
    uint32_t dst_ip6[4];
    uint32_t state;
};

#endif /* _LINUX_BPF_H */
