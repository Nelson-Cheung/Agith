#include "types.h"
#include "constant.h"
#include <linux/sched.h>

// create process or LWP
int kretprobe__copy_process(struct pt_regs *ctx)
{
    Event event = {};
    set_general_attribute(&event);
    event.type = HW_IPC_FORK;

    struct task_struct *proc = (struct task_struct *)PT_REGS_RC(ctx);

    if (is_err_ptr(proc))
    {
        event.arg0 = -1;
    }
    else
    {
        event.arg0 = proc->pid;
        event.arg1 = proc->tgid;
    }

    if (!filter(&event))
        return 0;

    // add new process to be monitored
    add_monitored_proc(event.pid, event.arg0);

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}

// exit
int kprobe__do_exit(long code)
{
    Event event = {};
    set_general_attribute(&event);
    event.type = HW_IPC_EXIT;

    if (!filter(&event))
        return 0;

    int key = event.pid;
    process_tree_record.delete(&key);

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
