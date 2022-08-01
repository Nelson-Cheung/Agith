from BPFFrame import BPFFrame
from ctypes import *
import os
from filter.net_send import net_send
from filter.net_recv import net_recv
from filter.general import general_print_header
from filter.ipc_exit import ipc_exit
from filter.ipc_fork import ipc_fork

handler_map = {
    0x0001: net_send,
    0x0002: net_recv,
    0x1001: ipc_fork,
    0x1002: ipc_exit
}

class Monitor():
    
    def __init__(self, pid):
        self.pid = c_int(pid)

        self.bf = BPFFrame(['types.h', 'ipc.c', 'unix.c', 'tcp.c'])
        self.bf.set_ringbuf_callback('buffer', self.callback)
        self.bf.get_table('process_tree_record')[c_int(pid)] = c_int(pid)

        print(f'my pid: {os.getpid()}')
        general_print_header()

    def run(self):
        self.bf.run()

    def callback(self, ctx, data, size):
        event = self.bf.get_ringbuf_event('buffer', data)
        if event.type in handler_map:
            handler_map[event.type](event)
        else:
            print('event %d not handled' % event.type)

    def run(self):
        self.bf.run()