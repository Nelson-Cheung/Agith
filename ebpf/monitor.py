from bcc import BPF
from utils import *
import time
import sys, getopt, os
from filter import *

print("loading bpf code...")

try:
    opts, args = getopt.getopt(sys.argv[1:], "", ["pid=", "name="])
except getopt.GetoptError:
    print("error")
    sys.exit(-1)

pid_tree = set()
comm_set = set()

for opt, arg in opts:
    if opt == "--pid":
        try:
            pid = int(arg)
            pid_tree.add(pid)
        except ValueError:
            print("error pid: %s" % arg)

    elif opt == "--name":
        comm_set.add(arg)

if len(pid_tree) == 0 and len(comm_set) == 0:
    print("error")
    sys.exit(-1)


bpf_prog = ""
bpf_prog += "\n" + load_kernel_functions("uprobe.c")
bpf_prog += "\n" + load_kernel_functions("net.c")
bpf_prog += "\n" + load_kernel_functions("ipc.c")
bpf_prog += "\n" + load_kernel_functions("fs.c")

bpf = BPF(text=bpf_prog)
bpf.attach_uretprobe(name="/bin/bash", sym="readline", fn_name="catch_command")

from filter import ipc_filter
from filter import fs_filter
from filter import net_filter
from filter import cmd_filter
from filter import opened_file

def events_handler(ctx, data, size):
    global monitor_pid
    event = bpf["events"].event(data)

    # flag = False
    comm = str(event.comm, "utf-8")
    if (event.pid not in pid_tree) and (comm not in comm_set):
        return

    if event.pid not in opened_file:
        opened_file[event.pid] = {}

    if event.type == 2 and event.arg1 > 0:
        pid_tree.add(event.arg1)
        # print("monitor pid adjust: {}".format(pid_tree))

    if event.type == 1:
        # print(pid_tree)
        pid_tree.remove(event.pid)
        # if len(pid_tree) == 0:
        #     flag = True

    if event.type < 1000:
        ipc_filter(bpf, event)

    elif event.type < 2000:
        fs_filter(bpf, event)

    elif event.type < 3000:
        net_filter(bpf, event)

    elif event.type == 4000:
        cmd_filter(bpf, event)

    else:
        print("Error")

bpf["events"].open_ring_buffer(events_handler)

for pid in pid_tree:
    opened_file[pid] = {}
    opened_file[pid][0] = "stdin"
    opened_file[pid][1] = "stdout"
    opened_file[pid][2] = "stderr"

print("Done")

print("%-18s %-16s %-5s %-6s %s" % ("time", "comm", "type", "pid", "action"))

while True:
    try:
        bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
