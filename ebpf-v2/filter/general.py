def general_print_header():
    print('%-32s%-8s%-8s %s' % ('program', 'pid', 'tgid', 'information'))

def general_print(event, info):
    print('%-32s%-8d%-8d %s' % (event.comm.decode(), event.pid, event.tgid, info))