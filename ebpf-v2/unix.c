#include "types.h"
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/pid.h>
#include <net/sock.h>
#include "constant.h"

int kprobe__unix_stream_sendmsg(struct pt_regs *ctx, struct socket *socket, struct msghdr *msg, size_t len)
{
    Event event = {};
    set_general_attribute(&event);
    event.type = HW_NET_SEND;

    if (!filter(&event))
        return 0;

    event.arg0 = HW_NET_UNIX;
    event.arg1 = socket->sk->sk_peer_pid->numbers[0].nr;

    if (event.arg1 > 0)
    {
        add_monitored_isolated_proc(event.arg1);
    }

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}

int kprobe__unix_dgram_sendmsg(struct pt_regs *ctx, struct socket *socket, struct msghdr *msg, size_t len)
{
    Event event = {};
    set_general_attribute(&event);
    event.type = HW_NET_SEND;

    if (!filter(&event))
        return 0;

    event.arg0 = HW_NET_UNIX;
    event.arg1 = socket->sk->sk_peer_pid->numbers[0].nr;

    if (event.arg1 > 0)
    {
        add_monitored_isolated_proc(event.arg1);
    }

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}

int kprobe__unix_stream_recvmsg(struct pt_regs *ctx, struct socket *socket, struct msghdr *msg,
                                size_t size, int flags)
{
    Event event = {};
    set_general_attribute(&event);
    event.type = HW_NET_RECV;

    int peer_pid = socket->sk->sk_peer_pid->numbers[0].nr;
    if (is_monitored(peer_pid))
    {
        add_monitored_isolated_proc(event.pid);
    }

    if (!filter(&event))
        return 0;

    event.arg0 = HW_NET_UNIX;
    event.arg1 = socket->sk->sk_peer_pid->numbers[0].nr;

    if (event.arg1 > 0)
    {
        add_monitored_proc(event.pid, event.arg0);
    }

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}

int kprobe__unix_dgram_recvmsg(struct pt_regs *ctx, struct socket *socket, struct msghdr *msg, size_t size, int flags)
{
    Event event = {};
    set_general_attribute(&event);
    event.type = HW_NET_RECV;

    int peer_pid = socket->sk->sk_peer_pid->numbers[0].nr;
    if (is_monitored(peer_pid))
    {
        add_monitored_isolated_proc(event.pid);
    }

    if (!filter(&event))
        return 0;

    event.arg0 = HW_NET_UNIX;
    event.arg1 = socket->sk->sk_peer_pid->numbers[0].nr;

    if (event.arg1 > 0)
    {
        add_monitored_proc(event.pid, event.arg0);
    }

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
