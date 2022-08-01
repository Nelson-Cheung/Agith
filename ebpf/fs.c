#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include "types.h"

struct chown_record_t
{
    int dfd;
    char filename[FILE_PATH_LEN];
    int user;
    int group;
};

BPF_HASH(chown_record, u64, struct chown_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_fchownat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t val = {};
    val.dfd = args->dfd;
    val.user = args->user;
    val.group = args->group;
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    chown_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchownat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t *val_ptr = chown_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHOWN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;

    surface.arg1 = 0;
    surface.arg2 = val_ptr->dfd;
    surface.arg3 = val_ptr->user;
    surface.arg4 = val_ptr->group;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
    
    chown_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t val = {};
    val.user = args->user;
    val.group = args->group;
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    chown_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t *val_ptr = chown_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHOWN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 1;
    surface.arg3 = val_ptr->user;
    surface.arg4 = val_ptr->group;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
    
    chown_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_lchown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t val = {};
    val.user = args->user;
    val.group = args->group;
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    chown_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_lchown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t *val_ptr = chown_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHOWN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 2;
    surface.arg3 = val_ptr->user;
    surface.arg4 = val_ptr->group;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
    
    chown_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t val = {};
    val.dfd = args->fd;
    val.user = args->user;
    val.group = args->group;
    chown_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chown_record_t *val_ptr = chown_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHOWN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 3;
    surface.arg2 = val_ptr->dfd;
    surface.arg3 = val_ptr->user;
    surface.arg4 = val_ptr->group;

    chown_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}
struct chdir_record_t
{
    char filename[FILE_PATH_LEN];
    int fd;
};

BPF_HASH(chdir_record, u64, struct chdir_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_chdir)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chdir_record_t val = {};
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    chdir_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chdir)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chdir_record_t *val_ptr = chdir_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHDIR;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = -1;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
    
    chdir_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchdir)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chdir_record_t val = {};
    val.fd = args->fd;
    chdir_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchdir)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chdir_record_t *val_ptr = chdir_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHDIR;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->fd;
    
    chdir_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

struct dup2_record_t
{
    int oldfd;
    int newfd;
};

BPF_HASH(dup2_record, u64, struct dup2_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_dup2)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dup2_record_t val = {};
    val.oldfd = args->oldfd;
    val.newfd = args->newfd;
    dup2_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup2)
{
    u64 key = bpf_get_current_pid_tgid();

    if (args->ret < 0)
    {
        dup2_record.delete(&key);
        return 0;
    }

    struct dup2_record_t *val_ptr = dup2_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_DUP2;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->oldfd;
    surface.arg2 = val_ptr->newfd;

    dup2_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dup2_record_t val = {};
    val.oldfd = args->fildes;
    dup2_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup)
{
    u64 key = bpf_get_current_pid_tgid();

    if (args->ret < 0)
    {
        dup2_record.delete(&key);
        return 0;
    }

    struct dup2_record_t *val_ptr = dup2_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_DUP2;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->oldfd;
    surface.arg2 = args->ret;

    dup2_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup3)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dup2_record_t val = {};
    val.oldfd = args->oldfd;
    val.newfd = args->newfd;
    dup2_record.update(&key, &val);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup3)
{
    u64 key = bpf_get_current_pid_tgid();

    if (args->ret < 0)
    {
        dup2_record.delete(&key);
        return 0;
    }

    struct dup2_record_t *val_ptr = dup2_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_DUP2;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->oldfd;
    surface.arg2 = val_ptr->newfd;

    dup2_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

struct rename_record_t
{
    int olddfd;
    int newdfd;
    char oldname[FILE_PATH_LEN];
    char newname[FILE_PATH_LEN];
};

BPF_HASH(rename_record, u64, struct rename_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_rename)
{
    u64 key = bpf_get_current_pid_tgid();
    struct rename_record_t val = {};

    bpf_probe_read_user_str(val.oldname, sizeof(val.oldname), args->oldname);
    bpf_probe_read_user_str(val.newname, sizeof(val.newname), args->newname);

    rename_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rename)
{
    u64 key = bpf_get_current_pid_tgid();
    struct rename_record_t *val_ptr = rename_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_RENAME;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->oldname);
    bpf_probe_read_kernel_str(surface.array2, sizeof(surface.array2), val_ptr->newname);
    surface.arg1 = -1;

    rename_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct rename_record_t val = {};

    val.olddfd = args->olddfd;
    val.newdfd = args->newdfd;
    bpf_probe_read_user_str(val.oldname, sizeof(val.oldname), args->oldname);
    bpf_probe_read_user_str(val.newname, sizeof(val.newname), args->newname);

    rename_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct rename_record_t *val_ptr = rename_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_RENAME;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->oldname);
    bpf_probe_read_kernel_str(surface.array2, sizeof(surface.array2), val_ptr->newname);
    surface.arg1 = val_ptr->olddfd;
    surface.arg2 = val_ptr->newdfd;

    rename_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2)
{
    u64 key = bpf_get_current_pid_tgid();
    struct rename_record_t val = {};

    val.olddfd = args->olddfd;
    val.newdfd = args->newdfd;
    bpf_probe_read_user_str(val.oldname, sizeof(val.oldname), args->oldname);
    bpf_probe_read_user_str(val.newname, sizeof(val.newname), args->newname);

    rename_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat2)
{
    u64 key = bpf_get_current_pid_tgid();
    struct rename_record_t *val_ptr = rename_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_RENAME;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->oldname);
    bpf_probe_read_kernel_str(surface.array2, sizeof(surface.array2), val_ptr->newname);
    surface.arg1 = val_ptr->olddfd;
    surface.arg2 = val_ptr->newdfd;

    rename_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

struct open_record_t
{
    int dfd;
    char filename[FILE_PATH_LEN];
};

BPF_HASH(open_record, u64, struct open_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u64 id = bpf_get_current_pid_tgid();
    struct open_record_t val = {};

    val.dfd = args->dfd;
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    open_record.update(&id, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_OPEN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.array1[0] = '\0';
    surface.arg1 = -1;

    u64 id = bpf_get_current_pid_tgid();
    struct open_record_t *val_ptr = open_record.lookup(&id);
    if (val_ptr)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
        surface.arg1 = val_ptr->dfd;
        open_record.delete(&id);
    }

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_creat)
{
    u64 id = bpf_get_current_pid_tgid();
    struct open_record_t val = {};

    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->pathname);
    open_record.update(&id, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_creat)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_OPEN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.array1[0] = '\0';
    surface.arg1 = -1;

    u64 id = bpf_get_current_pid_tgid();
    struct open_record_t *val_ptr = open_record.lookup(&id);

    if (val_ptr)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
        open_record.delete(&id);
    }

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_open)
{
    u64 id = bpf_get_current_pid_tgid();
    struct open_record_t val = {};

    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    open_record.update(&id, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_open)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_OPEN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.array1[0] = '\0';

    u64 id = bpf_get_current_pid_tgid();
    struct open_record_t *val_ptr = open_record.lookup(&id);
    if (val_ptr)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
        open_record.delete(&id);
    }

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

#include <uapi/linux/fcntl.h>

BPF_HASH(fcntl_record, u64, u32);

TRACEPOINT_PROBE(syscalls, sys_enter_fcntl)
{

    if (args->cmd == F_DUPFD_CLOEXEC || args->cmd == F_DUPFD)
    {
        u64 key = bpf_get_current_pid_tgid();
        u32 val = args->fd;
        fcntl_record.update(&key, &val);
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fcntl)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val = fcntl_record.lookup(&key);

    if (val)
    {
        struct general_surface_t surface = {};

        surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
        surface.timestamp = bpf_ktime_get_ns();
        surface.type = NR_FS_FCNTL;
        surface.ret = args->ret;
        bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
        surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
        surface.arg1 = *val;

        fcntl_record.delete(&key);
        events.ringbuf_output(&surface, sizeof(surface), 0);
    }

    return 0;
}

struct unlink_record_t
{
    int dfd;
    char filename[FILE_PATH_LEN];
};

BPF_HASH(unlink_record, u64, struct unlink_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct unlink_record_t val = {};

    val.dfd = args->dfd;
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->pathname);

    unlink_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct unlink_record_t *val_ptr = unlink_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_UNLINK;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->dfd;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
    
    unlink_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink)
{
    u64 key = bpf_get_current_pid_tgid();
    struct unlink_record_t val = {};

    val.dfd = -1;
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->pathname);

    unlink_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlink)
{
    u64 key = bpf_get_current_pid_tgid();
    struct unlink_record_t *val_ptr = unlink_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_UNLINK;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;

    surface.arg1 = val_ptr->dfd;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);

    unlink_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

BPF_HASH(rw_record, u64, u32);

TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_WRITE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;

    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_READ;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;

    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

struct mkdir_record_t
{
    int dfd;
    char pathname[FILE_PATH_LEN];
    int mode;
};

BPF_HASH(mkdir_record, u64, struct mkdir_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_mkdir)
{
    u64 key = bpf_get_current_pid_tgid();
    struct mkdir_record_t val = {};

    bpf_probe_read_user_str(val.pathname, sizeof(val.pathname), args->pathname);
    val.mode = args->mode;

    mkdir_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdir)
{
    u64 key = bpf_get_current_pid_tgid();
    struct mkdir_record_t *val_ptr = mkdir_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_MKDIR;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = -1;
    surface.arg2 = val_ptr->mode;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->pathname);

    mkdir_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct mkdir_record_t val = {};

    bpf_probe_read_user_str(val.pathname, sizeof(val.pathname), args->pathname);
    val.mode = args->mode;
    val.dfd = args->dfd;

    mkdir_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdirat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct mkdir_record_t *val_ptr = mkdir_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_MKDIR;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->dfd;
    surface.arg2 = val_ptr->mode;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->pathname);

    mkdir_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

struct symlink_record_t
{
    int newdfd;
    char oldname[FILE_PATH_LEN];
    char newname[FILE_PATH_LEN];
};

BPF_HASH(symlink_record, u64, struct symlink_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_symlinkat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct symlink_record_t val = {};

    bpf_probe_read_user_str(val.oldname, sizeof(val.oldname), args->oldname);
    bpf_probe_read_user_str(val.newname, sizeof(val.newname), args->newname);
    val.newdfd = args->newdfd;

    symlink_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlinkat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct symlink_record_t *val_ptr = symlink_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SOFT_LINK;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->oldname);
    bpf_probe_read_kernel_str(surface.array2, sizeof(surface.array2), val_ptr->newname);
    surface.arg1 = val_ptr->newdfd;

    symlink_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlink)
{
    u64 key = bpf_get_current_pid_tgid();
    struct symlink_record_t val = {};

    bpf_probe_read_user_str(val.oldname, sizeof(val.oldname), args->oldname);
    bpf_probe_read_user_str(val.newname, sizeof(val.newname), args->newname);
    val.newdfd = -1;

    symlink_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlink)
{
    u64 key = bpf_get_current_pid_tgid();
    struct symlink_record_t *val_ptr = symlink_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SOFT_LINK;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->oldname);
    bpf_probe_read_kernel_str(surface.array2, sizeof(surface.array2), val_ptr->newname);
    surface.arg1 = val_ptr->newdfd;

    symlink_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

struct link_record_t
{
    int newdfd;
    int olddfd;
    char oldname[FILE_PATH_LEN];
    char newname[FILE_PATH_LEN];
};

BPF_HASH(link_record, u64, struct link_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_linkat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct link_record_t val = {};

    bpf_probe_read_user_str(val.oldname, sizeof(val.oldname), args->oldname);
    bpf_probe_read_user_str(val.newname, sizeof(val.newname), args->newname);
    val.newdfd = args->newdfd;
    val.olddfd = args->olddfd;

    link_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_linkat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct link_record_t *val_ptr = link_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_HARD_LINK;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->oldname);
    bpf_probe_read_kernel_str(surface.array2, sizeof(surface.array2), val_ptr->newname);
    surface.arg1 = val_ptr->olddfd;
    surface.arg2 = val_ptr->newdfd;

    link_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_link)
{
    u64 key = bpf_get_current_pid_tgid();
    struct link_record_t val = {};

    bpf_probe_read_user_str(val.oldname, sizeof(val.oldname), args->oldname);
    bpf_probe_read_user_str(val.newname, sizeof(val.newname), args->newname);
    val.newdfd = -1;
    val.olddfd = -1;

    link_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_link)
{
    u64 key = bpf_get_current_pid_tgid();
    struct link_record_t *val_ptr = link_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_HARD_LINK;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->oldname);
    bpf_probe_read_kernel_str(surface.array2, sizeof(surface.array2), val_ptr->newname);
    surface.arg1 = val_ptr->olddfd;
    surface.arg2 = val_ptr->newdfd;

    link_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

struct chmod_record_t
{
    int dfd;
    char filename[FILE_PATH_LEN];
    int mode;
};

BPF_HASH(chmod_record, u64, struct chmod_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chmod_record_t val = {};

    val.dfd = args->dfd;
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    val.mode = args->mode;

    chmod_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmodat)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chmod_record_t *val_ptr = chmod_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHMOD;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->dfd;
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
    surface.arg2 = val_ptr->mode;

    chmod_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmod)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chmod_record_t val = {};

    val.dfd = args->fd;
    val.mode = args->mode;

    chmod_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmod)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chmod_record_t *val_ptr = chmod_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHMOD;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->dfd;
    surface.arg2 = val_ptr->mode;

    chmod_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chmod_record_t val = {};

    bpf_probe_read_user_str(val.filename, sizeof(val.filename), args->filename);
    val.mode = args->mode;

    chmod_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chmod)
{
    u64 key = bpf_get_current_pid_tgid();
    struct chmod_record_t *val_ptr = chmod_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CHMOD;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->filename);
    surface.arg2 = val_ptr->mode;
    surface.arg1 = -1;

    chmod_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

BPF_HASH(close_record, u64, u32);

TRACEPOINT_PROBE(syscalls, sys_enter_close)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 fd = args->fd;
    close_record.update(&key, &fd);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_close)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = close_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_CLOSE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;

    close_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sync)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SYNC;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = -1;

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_syncfs)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SYNC;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = args->fd;

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fsync)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SYNC;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = args->fd;

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fdatasync)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SYNC;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = args->fd;

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_truncate)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_TRUNCATE;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = -1;
    surface.arg2 = args->length;
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->path);
    
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_TRUNCATE;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = args->fd;
    surface.arg2 = args->length;
    
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknod)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_MKNOD;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = -1;
    surface.arg2 = args->mode;
    surface.arg3 = args->dev;
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->filename);
    
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknodat)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_MKNOD;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = args->dfd;
    surface.arg2 = args->mode;
    surface.arg3 = args->dev;
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->filename);
    
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

struct pipe_record_t
{
    int *fd_ptr;
};

BPF_HASH(pipe_record, u64, struct pipe_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_pipe)
{
    u64 key = bpf_get_current_pid_tgid();
    struct pipe_record_t val = {};
    val.fd_ptr = args->fildes;

    pipe_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe)
{
    if (args->ret < 0)
        return 0;

    u64 key = bpf_get_current_pid_tgid();
    struct pipe_record_t *val_ptr = pipe_record.lookup(&key);

    if (!val_ptr)
        return 0;

    int fd[2];
    bpf_probe_read_user(fd, sizeof(fd), val_ptr->fd_ptr);

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_PIPE;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = fd[0];
    surface.arg2 = fd[1];

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pipe2)
{
    u64 key = bpf_get_current_pid_tgid();
    struct pipe_record_t val = {};
    val.fd_ptr = args->fildes;

    pipe_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe2)
{
    if (args->ret < 0)
        return 0;

    u64 key = bpf_get_current_pid_tgid();
    struct pipe_record_t *val_ptr = pipe_record.lookup(&key);

    if (!val_ptr)
        return 0;

    int fd[2];
    bpf_probe_read_user(fd, sizeof(fd), val_ptr->fd_ptr);

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_PIPE;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = fd[0];
    surface.arg2 = fd[1];

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_futimesat)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_UTIME;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->filename);
    surface.arg1 = args->dfd;

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_utimensat)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_UTIME;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->filename);
    surface.arg1 = args->dfd;

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_utime)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_UTIME;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->filename);
    surface.arg1 = -1;

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_utimes)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_UTIME;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->filename);
    surface.arg1 = -1;

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_writev)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_writev)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_WRITE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;
    
    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_readv)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_readv)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_READ;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;

    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_WRITE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;
    
    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_READ;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;

    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev2)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev2)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_WRITE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;
    
    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv2)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv2)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_READ;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;
    
    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwrite64)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_WRITE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;
    
    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pread64)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 val = args->fd;

    rw_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pread64)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 *val_ptr = rw_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_READ;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = *val_ptr;
    
    rw_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

struct sendfile_record_t
{
    int out_fd;
    int in_fd;
};

BPF_HASH(sendfile_record, u64, struct sendfile_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_sendfile64)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t val = {};

    val.in_fd = args->in_fd;
    val.out_fd = args->out_fd;

    sendfile_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendfile64)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t *val_ptr = sendfile_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SENDFILE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->in_fd;
    surface.arg2 = val_ptr->out_fd;

    sendfile_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_splice)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t val = {};

    val.in_fd = args->fd_in;
    val.out_fd = args->fd_out;

    sendfile_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_splice)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t *val_ptr = sendfile_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SENDFILE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->in_fd;
    surface.arg2 = val_ptr->out_fd;
    
    sendfile_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tee)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t val = {};

    val.in_fd = args->fdin;
    val.out_fd = args->fdout;

    sendfile_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tee)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t *val_ptr = sendfile_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SENDFILE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->in_fd;
    surface.arg2 = val_ptr->out_fd;
    
    sendfile_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_copy_file_range)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t val = {};

    val.in_fd = args->fd_in;
    val.out_fd = args->fd_out;

    sendfile_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_copy_file_range)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sendfile_record_t *val_ptr = sendfile_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_SENDFILE;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->in_fd;
    surface.arg2 = val_ptr->out_fd;

    sendfile_record.delete(&key);
    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

// TRACEPOINT_PROBE(syscalls, sys_enter_fallocate)
// {
//     struct general_surface_t surface = {};

//     surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
//     surface.timestamp = bpf_ktime_get_ns();
//     surface.type = NR_FS_SENDFILE;

//     surface.fd = val_ptr->in_fd;
//     surface.length = val_ptr->out_fd;
//     surface.ret = args->ret;

//     sendfile_record.delete(&key);
//     events.ringbuf_output(&surface, sizeof(surface), 0);
//     return 0;
// }

TRACEPOINT_PROBE(syscalls, sys_enter_removexattr)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_XATTR;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 0;
    surface.arg2 = -1;
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->pathname);
    bpf_probe_read_user_str(surface.array2, sizeof(surface.array2), args->name);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_lremovexattr)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_XATTR;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 0;
    surface.arg2 = -1;
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->pathname);
    bpf_probe_read_user_str(surface.array2, sizeof(surface.array2), args->name);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fremovexattr)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_XATTR;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 0;
    surface.arg2 = args->fd;
    bpf_probe_read_user_str(surface.array2, sizeof(surface.array2), args->name);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setxattr)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_XATTR;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 1;
    surface.arg2 = -1;
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->pathname);
    bpf_probe_read_user_str(surface.array2, sizeof(surface.array2), args->name);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_lsetxattr)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_XATTR;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 1;
    surface.arg2 = -1;
    bpf_probe_read_user_str(surface.array1, sizeof(surface.array1), args->pathname);
    bpf_probe_read_user_str(surface.array2, sizeof(surface.array2), args->name);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fsetxattr)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_XATTR;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = 1;
    surface.arg2 = args->fd;
    bpf_probe_read_user_str(surface.array2, sizeof(surface.array2), args->name);

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fallocate)
{
    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_FS_FALLOCATE;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = args->fd;
    surface.arg2 = args->mode;
    surface.arg3 = args->len;
    surface.arg4 = args->offset;

    events.ringbuf_output(&surface, sizeof(surface), 0);
    return 0;
}
