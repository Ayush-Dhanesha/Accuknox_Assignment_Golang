/* Stub header for VS Code IntelliSense - BPF helpers */
#ifndef _BPF_BPF_HELPERS_H
#define _BPF_BPF_HELPERS_H

#include <stdint.h>

/* BPF helper function prototypes for IntelliSense */

/* Map operations */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *) 2;
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

/* Tracing */
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *) 6;

/* Time */
static uint64_t (*bpf_ktime_get_ns)(void) = (void *) 5;

/* Process info */
static uint64_t (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static uint64_t (*bpf_get_current_uid_gid)(void) = (void *) 15;
static int (*bpf_get_current_comm)(void *buf, int size_of_buf) = (void *) 16;

/* Network */
static uint32_t (*bpf_get_socket_cookie)(void *ctx) = (void *) 46;
static uint32_t (*bpf_get_socket_uid)(void *ctx) = (void *) 47;

/* Checksum */
static uint64_t (*bpf_csum_diff)(uint32_t *from, uint32_t from_size, uint32_t *to, uint32_t to_size, uint64_t seed) = (void *) 28;

/* String operations */
static int (*bpf_probe_read_str)(void *dst, uint32_t size, const void *unsafe_ptr) = (void *) 45;

/* Simplified printk macro */
#define bpf_printk(fmt, ...) \
    ({ \
        char ____fmt[] = fmt; \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

/* Memory operations */
static void *(*bpf_memset)(void *dest, int c, int n) = (void *) 0; /* Built-in */
static void *(*bpf_memcpy)(void *dest, const void *src, int n) = (void *) 0; /* Built-in */

/* Atomic operations (for stats) */
#define __sync_fetch_and_add(ptr, value) \
    ({ \
        typeof(*ptr) __old = *ptr; \
        *ptr += value; \
        __old; \
    })

/* License declaration */
#define LICENSE(x) char _license[] __attribute__((section("license"), used)) = x

#endif /* _BPF_BPF_HELPERS_H */
