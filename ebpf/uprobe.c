#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include "types.h"

int catch_command(struct pt_regs *ctx)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.type = NR_UPROBE_CMD;
    surface.timestamp = bpf_ktime_get_ns();

    if (!PT_REGS_RC(ctx))
        return 0;

    bpf_probe_read_user(&surface.array1, sizeof(surface.array1), (void *)PT_REGS_RC(ctx));

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
};
