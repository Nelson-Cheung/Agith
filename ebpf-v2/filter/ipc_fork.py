from .general import general_print

def ipc_fork(event):
    msg = 'fork new proc, pid: %d, tgid: %d' % (event.arg0, event.arg1) 
    general_print(event, msg)