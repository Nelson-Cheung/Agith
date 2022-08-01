#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include "types.h"

int kprobe__security_task_kill(struct pt_regs *ctx,
                               struct task_struct *p,
                               struct kernel_siginfo *info,
                               int sig,
                               const struct cred *cred)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_IPC_KILL;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;

    surface.arg1 = p->pid;
    surface.arg2 = sig;

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

int kprobe__do_exit(struct pt_regs *ctx)
{
    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_IPC_EXIT;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

int kretprobe__copy_process(struct pt_regs *ctx)
{
    struct task_struct *p = (struct task_struct *)PT_REGS_RC(ctx);
    
    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_IPC_FORK;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;

    surface.arg1 = p->pid;
    surface.arg2 = p->tgid;
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

// BPF_HASH(pvm_rw_record, u64, u32);

// TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_readv)
// {
//     u64 key = bpf_get_current_pid_tgid();
//     u32 val = args->pid;
//     pvm_rw_record.update(&key, &val);

//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_exit_process_vm_readv)
// {
//     u64 key = bpf_get_current_pid_tgid();
//     u32 *val_ptr = pvm_rw_record.lookup(&key);

//     if (!val_ptr) {
//         return 0;
//     }

//     struct general_surface_t surface = {};
//     surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
//     surface.timestamp = bpf_ktime_get_ns();

//     surface.type = NR_IPC_READ;
//     surface.ret = args->ret;
//     surface.another_pid = *val_ptr;

//     pvm_rw_record.delete(&key);

//     events.ringbuf_output(&surface, sizeof(surface), 0);

//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev)
// {
//     u64 key = bpf_get_current_pid_tgid();
//     u32 val = args->pid;
//     pvm_rw_record.update(&key, &val);

//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_exit_process_vm_writev)
// {
//     u64 key = bpf_get_current_pid_tgid();
//     u32 *val_ptr = pvm_rw_record.lookup(&key);

//     if (!val_ptr) {
//         return 0;
//     }

//     struct general_surface_t surface = {};
//     surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
//     surface.timestamp = bpf_ktime_get_ns();

//     surface.type = NR_IPC_WRITE;
//     surface.ret = args->ret;
//     surface.another_pid = *val_ptr;

//     pvm_rw_record.delete(&key);

//     events.ringbuf_output(&surface, sizeof(surface), 0);

//     return 0;
// }
