from .general import general_print
import socket
import struct

def net_recv(event):
    msg = ''
    if event.arg0 == 1:
        msg = 'proc %d recv bytes from proc %d via unix socket' % (event.tgid, event.arg1)
    elif event.arg0 == 2:
        ip = socket.inet_ntoa(struct.pack('i', event.arg3))
        port = socket.ntohs(event.arg4)
        msg = 'proc %d recv %d bytes from [ip: %s, port: %d]' % (event.pid, event.ret, ip, port)
    else:
        msg = 'net recv not handled'
    general_print(event, msg)