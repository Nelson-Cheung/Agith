import socket
import struct
from .general import general_print

def net_send(event):
    msg = ''
    if event.arg0 == 1:
        # unix
        msg = 'proc %d send bytes to proc %d via unix socket' % (event.pid, event.arg1)
    elif event.arg0 == 2:
        ip = socket.inet_ntoa(struct.pack('i', event.arg3))
        port = socket.ntohs(event.arg4)
        msg = 'proc %d send %d bytes to [ip: %s, port: %d]' % (event.pid, event.ret, ip, port)
    else:
        msg = 'net send not handled'
    general_print(event, msg)
