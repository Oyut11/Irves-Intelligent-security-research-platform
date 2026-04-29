/*
 * IRVES — eBPF Network Redirect Monitor Probe (CO-RE)
 *
 * Early-bird visibility layer for the transparent TCP redirect pipeline
 * (Phase 2B iptables nat OUTPUT rules do the actual redirection; this probe
 * captures connection attempts *before* the TLS handshake, providing:
 *   - Exact destination IP:port for every outbound connect()
 *   - PID and process name (comm) of the initiating thread
 *   - IPv4 and IPv6 support
 *   - Timestamp for latency correlation with mitmproxy flows
 *
 * Tracepoint: sys_enter_connect
 *   args[0] = fd   (int)
 *   args[1] = uservaddr (struct sockaddr __user *)
 *   args[2] = addrlen  (int)
 *
 * Load:  bpftool prog load net_redirect.bpf.o /sys/fs/bpf/irves_net_redirect
 * Attach: bpftool prog attach /sys/fs/bpf/irves_net_redirect \
 *             tracepoint syscalls:sys_enter_connect
 * Read:  cat /sys/kernel/debug/tracing/trace_pipe
 *        (also ringbuf-readable via bpftool map dump)
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* ── Address family constants (mirrors linux/socket.h) ──────────────── */
#define AF_INET   2
#define AF_INET6  10

/* ── Connect event emitted to ringbuf ───────────────────────────────── */

struct connect_event {
    u64 ts_ns;           /* bpf_ktime_get_ns() at entry */
    u32 pid;
    u32 tid;
    char comm[16];       /* process name */

    /* Address family: AF_INET (2) or AF_INET6 (10) */
    u16 af;
    u16 dport;           /* destination port, host byte order */
    u32 _pad;

    union {
        u8  v4[4];       /* IPv4 address (big-endian) */
        u8  v6[16];      /* IPv6 address */
    } daddr;

    int sockfd;
    u8  filtered;        /* 1 = high-value port (80/443/8080/8443) */
    u8  _pad2[3];
};

/* ── Ring buffer: 512 KB (network events are chatty) ────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} net_events SEC(".maps");

/* ── Per-CPU scratch for sockaddr reads ──────────────────────────────── */

struct sockaddr_scratch {
    u8 data[28];         /* large enough for sockaddr_in6 */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sockaddr_scratch);
} scratch_map SEC(".maps");

/* ── High-value port filter ──────────────────────────────────────────── */

static __always_inline u8 is_interesting_port(u16 port)
{
    return (port == 80 || port == 443 || port == 8080 ||
            port == 8443 || port == 4443 || port == 3000 ||
            port == 5000 || port == 9090);
}

/* ── Tracepoint: sys_enter_connect ───────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    int sockfd    = (int)ctx->args[0];
    void __user *uaddr = (void __user *)ctx->args[1];
    int addrlen   = (int)ctx->args[2];

    /* Only handle plausible IPv4/IPv6 addrlen */
    if (addrlen < 8 || addrlen > 28)
        return 0;

    /* Read sockaddr family first (2 bytes) */
    u16 af = 0;
    if (bpf_probe_read_user(&af, sizeof(af), uaddr) < 0)
        return 0;

    if (af != AF_INET && af != AF_INET6)
        return 0;

    /* Allocate ringbuf slot */
    struct connect_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;

    /* Fill metadata */
    u64 id = bpf_get_current_pid_tgid();
    e->pid    = id >> 32;
    e->tid    = (u32)id;
    e->ts_ns  = bpf_ktime_get_ns();
    e->sockfd = sockfd;
    e->af     = af;
    e->_pad   = 0;
    e->_pad2[0] = e->_pad2[1] = e->_pad2[2] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (af == AF_INET) {
        /* struct sockaddr_in: sa_family(2) + sin_port(2) + sin_addr(4) */
        struct {
            u16 family;
            u16 port;
            u8  addr[4];
        } sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->dport = bpf_ntohs(sin.port);
        __builtin_memcpy(e->daddr.v4, sin.addr, 4);
    } else {
        /* struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) */
        struct {
            u16 family;
            u16 port;
            u32 flowinfo;
            u8  addr[16];
        } sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uaddr) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->dport = bpf_ntohs(sin6.port);
        __builtin_memcpy(e->daddr.v6, sin6.addr, 16);
    }

    e->filtered = is_interesting_port(e->dport) ? 1 : 0;

    bpf_ringbuf_submit(e, 0);

    /* Also emit a trace_printk line so trace_pipe readers see it */
    if (e->filtered) {
        /* Note: bpf_trace_printk limited to 3 args — emit two separate calls */
        bpf_printk("irves_net: pid=%u port=%u af=%u\n",
                   (u32)(bpf_get_current_pid_tgid() >> 32),
                   (u32)e->dport,
                   (u32)af);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
