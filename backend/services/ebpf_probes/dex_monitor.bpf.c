/*
 * IRVES — eBPF DEX Monitor Probe (CO-RE)
 *
 * Watches memfd_create + mmap syscalls to detect runtime DEX unpacking.
 * When a packer (Qihoo, SecShell, Bangcle, etc.) decrypts a DEX into
 * anonymous memory, it creates an fd via memfd_create then mmaps it.
 *
 * This probe fires on:
 *   - sys_enter_memfd_create: captures the anonymous fd
 *   - sys_enter_mmap: when mapping non-file-backed regions, checks for
 *     DEX magic bytes (64 65 78 0a 30 33 35 00)
 *
 * Load via: bpftool prog load dex_monitor.bpf.o /sys/fs/bpf/irves_dex_monitor
 * Attach:   bpftool prog attach ... tracepoint syscalls:sys_enter_memfd_create
 *           bpftool prog attach ... tracepoint syscalls:sys_enter_mmap
 * Read:     cat /sys/kernel/debug/tracing/trace_pipe
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ── Ring buffer for events ──────────────────────────────────────────── */

struct dex_event {
    u32 pid;
    u32 tid;
    u64 addr;
    u64 size;
    s32 fd;
    char comm[16];
    u8  magic[8];
    u8  event_type;   /* 0 = memfd_create, 1 = mmap, 2 = dex_dump */
    u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB */
} events SEC(".maps");

/* ── Track anonymous fds from memfd_create ────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, s32);      /* fd */
    __type(value, u32);    /* pid that created it */
} anon_fds SEC(".maps");

/* ── Helper: submit event ────────────────────────────────────────────── */

static __always_inline void submit_event(
    struct trace_event_raw_sys_enter *ctx,
    u8 event_type, u64 addr, u64 size, s32 fd)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    struct dex_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->pid = pid;
    e->tid = tid;
    e->addr = addr;
    e->size = size;
    e->fd = fd;
    e->event_type = event_type;
    e->_pad[0] = e->_pad[1] = e->_pad[2] = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* If this is an mmap of a tracked anonymous fd, try to read DEX magic */
    if (event_type == 1 && fd >= 0) {
        /* Check if this fd was created by memfd_create (anonymous) */
        u32 *creator_pid = bpf_map_lookup_elem(&anon_fds, &fd);
        if (creator_pid) {
            /* Anonymous fd — attempt to read first 8 bytes from mapped addr */
            bpf_probe_read_user(&e->magic, 8, (void *)addr);
            /* DEX magic: 64 65 78 0a 30 33 35 00 */
            if (e->magic[0] == 0x64 && e->magic[1] == 0x65 &&
                e->magic[2] == 0x78 && e->magic[3] == 0x0a &&
                e->magic[4] == 0x30 && e->magic[5] == 0x33 &&
                e->magic[6] == 0x35) {
                e->event_type = 2;  /* dex_dump */
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
}

/* ── Tracepoint: sys_enter_memfd_create ───────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    /* The return value (fd) isn't available at sys_enter.
       We track it at sys_exit instead. But we can still log the event. */
    submit_event(ctx, 0, 0, 0, -1);

    return 0;
}

/* ── Tracepoint: sys_exit_memfd_create ────────────────────────────────── */

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int trace_memfd_create_ret(struct trace_event_raw_sys_exit *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    s32 fd = (s32)ctx->ret;

    if (fd >= 0) {
        /* Record this fd as anonymous (memfd-created) */
        bpf_map_update_elem(&anon_fds, &fd, &pid, BPF_ANY);
    }

    return 0;
}

/* ── Tracepoint: sys_enter_mmap ───────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    u64 addr = ctx->args[0];  /* addr (hint) */
    u64 len  = ctx->args[1];  /* length */
    s32 prot = (s32)ctx->args[2];
    s32 flags = (s32)ctx->args[3];
    s32 fd   = (s32)ctx->args[4];

    /* We only care about:
       - fd >= 0 (file-backed, might be our anon fd)
       - or MAP_ANONYMOUS (fd == -1 but still interesting for packers)
       Focus on file-backed mmaps that could be our tracked anon fds */
    if (fd >= 0) {
        u32 *creator_pid = bpf_map_lookup_elem(&anon_fds, &fd);
        if (creator_pid) {
            /* This mmap targets an anonymous fd from memfd_create */
            submit_event(ctx, 1, addr, len, fd);
        }
    }

    return 0;
}

/* ── Tracepoint: sys_enter_munmap ─────────────────────────────────────── */
/* Track munmap to clean up — packers often unmap after reading */

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx)
{
    /* Could track unmapped regions for correlation, but not critical */
    return 0;
}

/* ── Cleanup: close removes anon fd tracking ─────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
    s32 fd = (s32)ctx->args[0];
    if (fd >= 0) {
        bpf_map_delete_elem(&anon_fds, &fd);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
