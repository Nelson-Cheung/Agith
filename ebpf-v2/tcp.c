#include "types.h"
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/pid.h>
#include <net/inet_sock.h>
#include "constant.h"

#define LOCALHOST 16777343

BPF_HASH(port_pid_map, struct int_pair, int);

struct tcp_params
{
    int src_addr;
    int src_port;
    int dst_addr;
    int dst_port;
};

BPF_HASH(temp_param_map, u64, struct tcp_params);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *socket, struct msghdr *msg, size_t size)
{
    struct inet_sock *inet = (struct inet_sock *)socket;

    u64 key = bpf_get_current_pid_tgid();
    struct tcp_params params = {
        .src_addr = inet->inet_saddr,
        .src_port = inet->inet_sport,
        .dst_addr = inet->inet_daddr,
        .dst_port = inet->inet_dport};
    temp_param_map.update(&key, &params);
    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct tcp_params *params_ptr = temp_param_map.lookup(&key);
    if (!params_ptr)
    {
        return 0;
    }

    Event event = {};
    set_general_attribute(&event);
    event.ret = (int)PT_REGS_RC(ctx);
    event.type = HW_NET_SEND;

    if (!filter(&event))
    {
        return 0;
    }

    event.arg0 = HW_NET_TCP;
    event.arg1 = params_ptr->src_addr;
    event.arg2 = params_ptr->src_port;
    event.arg3 = params_ptr->dst_addr;
    event.arg4 = params_ptr->dst_port;

    if (params_ptr->dst_addr == LOCALHOST)
    {
        struct int_pair key = {.first = params_ptr->src_port, .second = params_ptr->dst_port};
        int pid = event.pid;
        port_pid_map.update(&key, &pid);
    }

    buffer.ringbuf_output(&event, sizeof(event), 0);

    temp_param_map.delete(&key);
    return 0;
}

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *socket, struct msghdr *msg, size_t len, int flags, int *addr_len)
{
    struct inet_sock *inet = (struct inet_sock *)socket;

    u64 key = bpf_get_current_pid_tgid();
    struct tcp_params params = {
        .src_addr = inet->inet_saddr,
        .src_port = inet->inet_sport,
        .dst_addr = inet->inet_daddr,
        .dst_port = inet->inet_dport};
    temp_param_map.update(&key, &params);
    return 0;
}

int kretprobe__tcp_recvmsg(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct tcp_params *params_ptr = temp_param_map.lookup(&key);
    if (!params_ptr)
    {
        return 0;
    }

    Event event = {};
    set_general_attribute(&event);
    event.ret = (int)PT_REGS_RC(ctx);
    event.type = HW_NET_RECV;

    if (params_ptr->dst_addr == LOCALHOST)
    {
        struct int_pair key = {.first = params_ptr->dst_port, .second = params_ptr->src_port};
        int *val_ptr = port_pid_map.lookup(&key);
        if (val_ptr)
        {
            add_monitored_isolated_proc(event.pid);
        }
    }

    if (!filter(&event))
    {
        return 0;
    }

    event.arg0 = HW_NET_TCP;
    event.arg1 = params_ptr->src_addr;
    event.arg2 = params_ptr->src_port;
    event.arg3 = params_ptr->dst_addr;
    event.arg4 = params_ptr->dst_port;

    buffer.ringbuf_output(&event, sizeof(event), 0);

    temp_param_map.delete(&key);

    return 0;
}
