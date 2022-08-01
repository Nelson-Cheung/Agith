#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/un.h>
#include <linux/netlink.h>
#include "types.h"

struct debug_record_t
{
    int arg1;
    int arg2;
    int arg3;
};

struct sockaddr_record_t
{
    int family;
    int fd;

    int ip;
    int port;

    int nl_pid;
    int nl_groups;

    char path[109];
};

BPF_HASH(bind_record, u64, struct sockaddr_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_bind)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t val = {};
    val.fd = args->fd;
    val.family = -1;

    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(sa_family_t), args->umyaddr);

    val.family = family;
    if (val.family == AF_UNIX)
    {
        struct sockaddr_un addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->umyaddr);
        bpf_probe_read_kernel_str(val.path, sizeof(val.path), addr.sun_path);
    }
    else if (val.family == AF_INET)
    {
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->umyaddr);
        val.port = addr.sin_port & 0xffff;
        val.ip = addr.sin_addr.s_addr;
    }
    else if (val.family == AF_NETLINK)
    {
        struct sockaddr_nl addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->umyaddr);
        val.nl_pid = addr.nl_pid;
        val.nl_groups = addr.nl_groups;
    }

    bind_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_bind)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t *val_ptr = bind_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_BIND;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;

    surface.arg1 = val_ptr->fd;
    surface.arg2 = val_ptr->family;

    if (val_ptr->family == AF_INET)
    {
        surface.arg3 = val_ptr->ip;
        surface.arg4 = val_ptr->port;
    }
    else if (val_ptr->family == AF_UNIX)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->path);
    }
    else if (val_ptr->family == AF_NETLINK)
    {
        surface.arg3 = val_ptr->nl_pid;
        surface.arg4 = val_ptr->nl_groups;
    }

    bind_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

BPF_HASH(accept_record, u64, struct sockaddr_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_accept)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t val = {};
    val.fd = args->fd;

    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(sa_family_t), args->upeer_sockaddr);

    val.family = family;
    if (val.family == AF_UNIX)
    {
        struct sockaddr_un addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->upeer_sockaddr);
        bpf_probe_read_kernel_str(val.path, sizeof(val.path), addr.sun_path);
    }
    else if (val.family == AF_INET)
    {
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->upeer_sockaddr);
        val.port = addr.sin_port & 0xffff;
        val.ip = addr.sin_addr.s_addr;
    }

    accept_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t *val_ptr = accept_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_ACCEPT;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->fd;
    surface.arg2 = val_ptr->family;

    if (val_ptr->family == AF_INET)
    {
        surface.arg3 = val_ptr->ip;
        surface.arg4 = val_ptr->port;
    }
    else if (val_ptr->family == AF_UNIX)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->path);
    }

    accept_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

BPF_HASH(connect_record, u64, struct sockaddr_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t val = {};

    val.fd = args->fd;

    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(sa_family_t), args->uservaddr);

    val.family = family;
    if (val.family == AF_UNIX)
    {
        struct sockaddr_un addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);
        bpf_probe_read_kernel_str(val.path, sizeof(val.path), addr.sun_path);
    }
    else if (val.family == AF_INET)
    {
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);
        val.port = addr.sin_port & 0xffff;
        val.ip = addr.sin_addr.s_addr;
    }

    connect_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t *val_ptr = connect_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_CONNECT;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->fd;
    surface.arg2 = val_ptr->family;

    if (val_ptr->family == AF_UNIX)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->path);
    }
    else if (val_ptr->family == AF_INET)
    {
        surface.arg3 = val_ptr->ip;
        surface.arg4 = val_ptr->port;
    }

    connect_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t val = {};
    val.fd = args->fd;

    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(sa_family_t), args->upeer_sockaddr);

    val.family = family;
    if (val.family == AF_UNIX)
    {
        struct sockaddr_un addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->upeer_sockaddr);
        bpf_probe_read_kernel_str(val.path, sizeof(val.path), addr.sun_path);
    }
    else if (val.family == AF_INET)
    {
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->upeer_sockaddr);
        val.port = addr.sin_port & 0xffff;
        val.ip = addr.sin_addr.s_addr;
    }

    accept_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4)
{
    u64 key = bpf_get_current_pid_tgid();
    struct sockaddr_record_t *val_ptr = accept_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_ACCEPT;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->fd;
    surface.arg2 = val_ptr->family;

    if (val_ptr->family == AF_INET)
    {
        surface.arg3 = val_ptr->ip;
        surface.arg4 = val_ptr->port;
    }
    else if (val_ptr->family == AF_UNIX)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->path);
    }

    accept_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

struct send_recv_record_t
{
    struct sockaddr_record_t addr;
    int type;
};

BPF_HASH(send_recv_record, u64, struct send_recv_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t val = {};

    val.addr.fd = args->fd;
    val.type = 1;

    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(sa_family_t), args->addr);

    val.addr.family = family;
    if (val.addr.family == AF_UNIX)
    {
        struct sockaddr_un addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->addr);
        bpf_probe_read_kernel_str(val.addr.path, sizeof(val.addr.path), addr.sun_path);
    }
    else if (val.addr.family == AF_INET)
    {
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->addr);
        val.addr.port = addr.sin_port & 0xffff;
        val.addr.ip = addr.sin_addr.s_addr;
    }

    send_recv_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t *val_ptr = send_recv_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_SENDMSG;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->addr.fd;
    surface.arg2 = val_ptr->type;
    surface.arg3 = val_ptr->addr.family;

    if (val_ptr->addr.family == AF_INET)
    {
        surface.arg4 = val_ptr->addr.ip;
        surface.arg5 = val_ptr->addr.port;
    }
    else if (val_ptr->addr.family == AF_UNIX)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->addr.path);
    }

    send_recv_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t val = {};

    val.addr.fd = args->fd;
    val.type = 2;
    send_recv_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t *val_ptr = send_recv_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_SENDMSG;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->addr.fd;
    surface.arg2 = val_ptr->type;

    send_recv_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t val = {};

    val.addr.fd = args->fd;
    val.type = 3;
    send_recv_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t *val_ptr = send_recv_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_SENDMSG;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->addr.fd;
    surface.arg2 = val_ptr->type;

    send_recv_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t val = {};

    val.addr.fd = args->fd;
    val.type = 1;

    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(sa_family_t), args->addr);

    val.addr.family = family;
    if (val.addr.family == AF_UNIX)
    {
        struct sockaddr_un addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->addr);
        bpf_probe_read_kernel_str(val.addr.path, sizeof(val.addr.path), addr.sun_path);
    }
    else if (val.addr.family == AF_INET)
    {
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), args->addr);
        val.addr.port = addr.sin_port & 0xffff;
        val.addr.ip = addr.sin_addr.s_addr;
    }
    else
    {
        if (args->addr_len)
        {
            bpf_probe_read_user(&val.addr.ip, sizeof(int), args->addr_len);
        }
        else
        {
            val.addr.ip = -1;
        }
    }

    send_recv_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t *val_ptr = send_recv_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_RECVMSG;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->addr.fd;
    surface.arg2 = val_ptr->type;
    surface.arg3 = val_ptr->addr.family;

    if (val_ptr->addr.family == AF_INET)
    {
        surface.arg4 = val_ptr->addr.ip;
        surface.arg5 = val_ptr->addr.port;
    }
    else if (val_ptr->addr.family == AF_UNIX)
    {
        bpf_probe_read_kernel_str(surface.array1, sizeof(surface.array1), val_ptr->addr.path);
    }

    send_recv_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t val = {};

    val.addr.fd = args->fd;
    val.type = 2;
    send_recv_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t *val_ptr = send_recv_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_RECVMSG;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->addr.fd;
    surface.arg2 = val_ptr->type;

    send_recv_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t val = {};

    val.addr.fd = args->fd;
    val.type = 3;
    send_recv_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmmsg)
{
    u64 key = bpf_get_current_pid_tgid();
    struct send_recv_record_t *val_ptr = send_recv_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_RECVMSG;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->addr.fd;
    surface.arg2 = val_ptr->type;

    send_recv_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

struct shutdown_record_t
{
    int fd;
    int how;
};

BPF_HASH(shutdown_record, u64, struct shutdown_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_shutdown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct shutdown_record_t val = {};

    val.fd = args->fd;
    val.how = args->how;

    shutdown_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_shutdown)
{
    u64 key = bpf_get_current_pid_tgid();
    struct shutdown_record_t *val_ptr = shutdown_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};
    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_SHUTDOWN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->fd;
    surface.arg2 = val_ptr->how;

    shutdown_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

struct socket_record_t
{
    int family;
    int type;
    int protocol;
    int *socket_pair;
};

BPF_HASH(socket_record, u64, struct socket_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_socket)
{
    u64 key = bpf_get_current_pid_tgid();
    struct socket_record_t val = {};

    val.family = args->family;
    val.protocol = args->protocol;
    val.type = args->type;

    socket_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socket)
{
    u64 key = bpf_get_current_pid_tgid();
    struct socket_record_t *val_ptr = socket_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_CREATE_SOCKET;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->family;
    surface.arg2 = val_ptr->protocol;
    surface.arg3 = val_ptr->type;
    surface.arg4 = -1;

    socket_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_socketpair)
{
    u64 key = bpf_get_current_pid_tgid();
    struct socket_record_t val = {};

    val.family = args->family;
    val.protocol = args->protocol;
    val.type = args->type;
    val.socket_pair = args->usockvec;

    socket_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socketpair)
{
    u64 key = bpf_get_current_pid_tgid();
    struct socket_record_t *val_ptr = socket_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_CREATE_SOCKET;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->family;
    surface.arg2 = val_ptr->protocol;
    surface.arg3 = val_ptr->type;

    int socket_pair[2];
    bpf_probe_read_user(socket_pair, sizeof(socket_pair), val_ptr->socket_pair);
    surface.arg4 = socket_pair[0];
    surface.arg5 = socket_pair[1];

    socket_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}

struct listen_record_t
{
    int fd;
    int backlog;
};

BPF_HASH(listen_record, u64, struct listen_record_t);

TRACEPOINT_PROBE(syscalls, sys_enter_listen)
{
    u64 key = bpf_get_current_pid_tgid();
    struct listen_record_t val = {};

    val.fd = args->fd;
    val.backlog = args->backlog;

    listen_record.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_listen)
{
    u64 key = bpf_get_current_pid_tgid();
    struct listen_record_t *val_ptr = listen_record.lookup(&key);

    if (!val_ptr)
    {
        return 0;
    }

    struct general_surface_t surface = {};

    surface.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    surface.timestamp = bpf_ktime_get_ns();
    surface.type = NR_NET_LISTEN;
    surface.ret = args->ret;
    bpf_get_current_comm(&surface.comm, sizeof(surface.comm));
    surface.tgid = (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;
    
    surface.arg1 = val_ptr->fd;
    surface.arg2 = val_ptr->backlog;

    listen_record.delete(&key);

    events.ringbuf_output(&surface, sizeof(surface), 0);

    return 0;
}
