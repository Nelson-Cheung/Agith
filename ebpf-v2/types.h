#ifndef TYPES_H
#define TYPES_H

// ring buffer event
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

typedef struct
{
    // general attribute
    int pid;
    int tgid;
    int ret;
    int type;
    long long timestamp;
    char comm[16];

    int arg0;
    int arg1;
    int arg2;
    int arg3;
    int arg4;

} Event;

// process tree record, key: pid, value: ppid
BPF_HASH(process_tree_record, int, int);

static void set_general_attribute(Event *event)
{
    event->pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event->tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&(event->comm), sizeof(event->comm));
}

static int get_proc_tree_record(int pid)
{
    int *val = process_tree_record.lookup(&pid);
    if (val)
    {
        return *val;
    }
    else
    {
        return pid;
    }
}

static int is_err_ptr(void *p)
{
    return (unsigned long)p >= 0xfffffffffffff000UL;
}

static int filter(Event *event)
{
    int key = event->pid;
    int *val_ptr = process_tree_record.lookup(&key);

    return (val_ptr != NULL);
}

static int add_monitored_proc(int pid, int new_pid)
{
    // add new process to process tree
    int *val_ptr = process_tree_record.lookup(&pid);
    if (!val_ptr)
        return -1;

    int val = *val_ptr;
    process_tree_record.update(&new_pid, &val);

    return 0;
}

static int add_monitored_isolated_proc(int pid)
{
    // add new process to process tree
    int *val_ptr = process_tree_record.lookup(&pid);
    if (val_ptr)
        return 0;

    int val = pid;
    process_tree_record.update(&pid, &val);

    return 0;
}

static int is_monitored(int pid)
{
    int *val_ptr = process_tree_record.lookup(&pid);
    return (val_ptr != NULL);
}
struct int_pair
{
    int first, second;
};
#endif
