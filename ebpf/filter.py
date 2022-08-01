import socket
import struct
import time
import copy

DEBUG = True

opened_file = {}
input_cmd = ""
modify_object = []

def check(event):
    if event.tgid not in opened_file:
        opened_file[event.tgid] = {}
        if DEBUG:
            print("crete an empty fd list for proc %d" % event.pid)
    
def fd2path(tgid, fd):
    if fd not in opened_file[tgid]:
        return ""

    return opened_file[tgid][fd]

def ipc_filter(bpf, event):
    comm = str(event.comm, "utf-8")

    if event.type == 0:
        # kill
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "ipc", event.pid, "kill %d, signal %d" % (event.arg1, event.arg2)))
        global modify_object
        modify_object.append("kill %d, signal %d" % (event.arg1, event.arg2))

    elif event.type == 1:
        # exit
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "ipc", event.pid, "exit"))
        # Q: 主线程退出，其他线程退出？
        if event.pid in opened_file:
            opened_file.pop(event.pid)

    elif event.type == 2:
        # fork
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "ipc", event.pid, "create process %d" % (event.arg1)))
        # Q: fork出来的一定是进程？
        if event.tgid != event.arg2:
            opened_file[event.arg1] = opened_file[event.tgid].copy()
        if DEBUG:  
            pass
        # opened_file[event.arg1][0] = "stdin"
        # opened_file[event.arg1][1] = "stdout"
        # opened_file[event.arg1][2] = "stderr"

    # elif event.type == 3:
    #     print("%-18d %-5s %-6d %s" % (event.timestamp, "ipc", event.pid, "read %d bytes from proc %d" % (event.ret, event.another_pid)))
    
    # elif event.type == 4:
    #     print("%-18d %-5s %-6d %s" % (event.timestamp, "ipc", event.pid, "write %d bytes to proc %d" % (event.ret, event.another_pid)))

    elif event.type == -1:
        if DEBUG:
            print("exit", event.pid)

def fs_filter(bpf, event):
    comm = str(event.comm, "utf-8")
    
    global modify_object

    if event.type == 1000:
        # create
        path = str(event.array1, "utf-8")
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "create file %s" % (path)))
    
    elif event.type == 1001:
        check(event)
        path = str(event.array1, "utf-8")
        another_path = str(event.array2, "utf-8")

        if event.arg1 > 0 and event.arg1 in opened_file[event.tgid]:
            another_path = opened_file[event.tgid][event.arg1] + "/" + another_path
        
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "soft link %s to %s" % (another_path, path)))

        modify_object.append("soft link %s to %s" % (another_path, path))

    elif event.type == 1002:
        check(event)
        path = str(event.array1, "utf-8")

        if event.arg1 > 0 and event.arg1 in opened_file[event.tgid]:
            path = opened_file[event.tgid][event.arg1] + "/" + path

        another_path = str(event.array2, "utf-8")

        if event.arg2 > 0 and event.arg2 in opened_file[event.tgid]:
            another_path = opened_file[event.tgid][event.arg2] + "/" + another_path

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "hard link %s to %s" % (another_path, path)))
    
        modify_object.append("hard link %s to %s" % (another_path, path))

    elif event.type == 1003:
        check(event)
        if event.ret != 0:
            return
        
        path = str(event.array1, "utf-8")

        if event.arg1 > 0:
            if event.arg1 in opened_file[event.tgid]:
                path = opened_file[event.tgid][event.arg1] + "/" + path
            else:
                if DEBUG:
                    print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))
                return 

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "remove file %s" % (path)))        

        modify_object.append("remove file %s" % (path))

    elif event.type == 1004:
        check(event)
        if event.ret < 0:
            return

        path = str(event.array1, "utf-8")
        if event.arg1 >= 0:
            if event.arg1 not in opened_file[event.tgid]:
                if DEBUG:
                    print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))

            dirname = opened_file[event.tgid][event.arg1]
            path = dirname + "/" + path        

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "create dir %s" % (path)))      

        modify_object.append("create dir %s" % (path))

    # elif event.type == 5:
    #     path = str(event.path, "utf-8")
    #     print("%-18d %-5s %-6d %s" % (event.timestamp, "fs", event.pid, "remove dir %s" % (path)))

    #     modify_object.append("remove dir %s" % (path))

    elif event.type == 1006:
        path = str(event.array1, "utf-8")
        another_path = str(event.array2, "utf-8")

        if event.arg1 != -1:
            dir_name = fd2path(event.tgid, event.arg1)
            if len(dir_name) > 0:
                path = dir_name + "/" + path
            dir_name = fd2path(event.tgid, event.arg2)
            if len(dir_name) > 0:
                another_path = dir_name + "/" + another_path           

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "rename %s --> %s" % (path, another_path)))

        modify_object.append("rename %s --> %s" % (path, another_path))

    elif event.type == 1007:
        check(event)
        # open, openat
        if event.ret < 0:
            return
        
        if event.pid not in opened_file:
            if DEBUG:
                print("fs %d error: proc %d opened files not catched" % (event.type, event.pid))

        path = str(event.array1, "utf-8")

        if event.arg1 >= 0:
            if event.arg1 not in opened_file[event.tgid]:
                if DEBUG:
                    print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))
                return
            dirname = opened_file[event.tgid][event.arg1]
            path = dirname + "/" + path

        opened_file[event.tgid][event.ret] = path
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "open file %s, fd %d" % (path, event.ret)))   

    elif event.type == 1008:      
        check(event)
        if event.pid not in opened_file:
            return

        if event.arg1 not in opened_file[event.tgid]:
            if DEBUG:
                print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))
            return

        path = opened_file[event.tgid][event.arg1]
        # print(event.pid, event.arg1, path)
        if type(path) == str:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "read %d bytes from %s" % (event.ret, path))) 
        elif path["file_type"] == "socket":
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "read %d bytes from sock %d" % (event.ret, event.arg1)))
            modify_object.append("read %d bytes from sock %d" % (event.ret, event.arg1))

    elif event.type == 1009:
        check(event)
        if event.pid not in opened_file:
            return

        if event.arg1 not in opened_file[event.tgid]:
            if DEBUG:
                print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))
            return

        path = opened_file[event.tgid][event.arg1]
        # print(event.pid, event.arg1, path)
        if type(path) == str:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "write %d bytes to %s" % (event.ret, path))) 
            if path not in ["stdin", "stdout", "stderr", "/dev/tty", "/dev/null"] and path.find("pipe") == -1:
                modify_object.append("write %d bytes to %s" % (event.ret, path))

        elif path["file_type"] == "socket":
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "write %d bytes to sock %d" % (event.ret, event.arg1)))
            modify_object.append("write %d bytes to sock %d" % (event.ret, event.arg1))
            

    elif event.type == 1010:
        check(event)
        if event.ret < 0:
            return
        
        path = ""
        if event.arg1 == -1:
            path = str(event.array1, "utf-8")
        else:
            if event.arg1 in opened_file[event.tgid]:
                path = opened_file[event.tgid][event.arg1]

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "chdir %s" % (path)))

    elif event.type == 1011:
        check(event)
        newfd = event.arg2
        oldfd = event.arg1

        # print("fd %d, count %d" % (event.fd, event.length))
        if event.pid in opened_file:
            if oldfd in opened_file[event.tgid]:
                # path = opened_file[event.tgid][oldfd]
                # opened_file[event.tgid].pop(oldfd)
                opened_file[event.tgid][newfd] = copy.copy(opened_file[event.tgid][oldfd])
                # print("%-18d %-5s %-6d %s" % (event.timestamp, "fs", event.pid, "chdir %s" % (path)))
            else:
                if DEBUG:
                    print("fs %d error: fd %d not in proc %d opened files" % (event.type, oldfd, event.pid))

    elif event.type == 1012:
        check(event)
        if event.ret <= 0:
            return
        
        if event.pid not in opened_file:
            return

        if event.arg1 not in opened_file[event.tgid]:
            if DEBUG:
                print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))
            return

        opened_file[event.tgid][event.ret] = copy.copy(opened_file[event.tgid][event.arg1])

    elif event.type == 1013:
        check(event)
        if event.ret < 0:
            return
        
        if event.pid not in opened_file:
            opened_file[event.tgid] = {}

        path = str(event.array1, "utf-8")
        if event.arg1 >= 0:
            if event.arg1 not in opened_file[event.tgid]:
                if DEBUG:
                    print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))
                return
            dirname = opened_file[event.tgid][event.arg1]
            if len(path) > 0:
                path = dirname + "/" + path
            else:
                path = dirname

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "chmod %s to %o" % (path, event.arg2)))    

        modify_object.append("chmod %s to %o" % (path, event.arg2))

    elif event.type == 1014:
        check(event)
        if event.ret < 0:
            return
        
        path = ""
        if event.arg1 == 0 or event.arg1 == 1 or event.arg1 == 2:
            path = str(event.array1, "utf-8")
        if ( event.arg1 == 0 or event.arg1 == 3 )and event.arg2 >= 0:
            if event.arg2 not in opened_file[event.tgid]:
                if DEBUG:
                    print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg2, event.pid))
                return
            dirname = opened_file[event.tgid][event.arg2]
            if event.arg1 == 0:
                path = dirname + "/" + path
            elif event.arg1 == 3:
                path = dirname

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "chown %s to %d:%d" % (path, event.arg3, event.arg4)))
        modify_object.append("chown %s to %d:%d" % (path, event.arg3, event.arg4))

    elif event.type == 1015:
        check(event)
        if event.arg1 >= 0:
            if event.arg1 not in opened_file[event.tgid]:
                # 多次close，没有问题，不显示错误
                # print("fs %d error: fd %d not in proc %d opened files" % (event.type, event.arg1, event.pid))
                return
            opened_file[event.tgid].pop(event.arg1)
        if DEBUG:    
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "close fd %d, ret %d" % (event.arg1, event.ret)))

    elif event.type == 1016:
        if event.arg1 == -1:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "sync all files"))
            modify_object.append("sync all files")
        else:
            path = fd2path(event.tgid, event.arg1)
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "sync file %s" % (path)))
            modify_object.append("sync file %s" % (path))


    elif event.type == 1017:
        path = ""
        if event.arg1 == -1:
            path = str(event.array1, "utf-8")
        else:
            path = fd2path(event.tgid, event.arg1)

        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "truncate file %s to length %d" % (path, event.arg2)))
        modify_object.append("truncate file %s to length %d" % (path, event.arg2))

    elif event.type == 1018:
        path = ""
        if event.arg1 == -1:
            path = str(event.array1, "utf-8")
        else:
            dir_name = fd2path(event.tgid, event.arg1)
            if len(dir_name) > 0:
                path = dir_name + "/" + path
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "create special file %s, mode %o, dev %d" % (path, event.arg2, event.arg3)))
        modify_object.append("create special file %s, mode %o, dev %d" % (path, event.arg2, event.arg3))

    elif event.type == 1019:
        check(event)
        opened_file[event.tgid][event.arg1] = str(event.arg1) + "(read pipe)"
        opened_file[event.tgid][event.arg2] = str(event.arg2) + "(write pipe)"
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "create write pipe %d, read pipe %d" % (event.arg1, event.arg2)))
    
    elif event.type == 1020:
        path = str(event.array1, "utf-8")
        if event.arg1 > 0:
            dir_name = fd2path(event.tgid, event.arg1)
            if len(dir_name) > 0:
                path = dir_name + "/" + path
        
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "change modify and access time of file %s" % (path)))

        modify_object.append("change modify and access time of file %s" % (path))

    elif event.type == 1021:
        in_path = fd2path(event.tgid, event.arg1)
        out_path = fd2path(event.tgid, event.arg2)
        
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "send %d bytes from %s to %s" % (event.ret, in_path, out_path)))

        modify_object.append("send %d bytes from %s to %s" % (event.ret, in_path, out_path))

    elif event.type == 1022:

        if event.arg1 == 0:
            name = str(event.array2, "utf-8")
            path = ""
            if event.arg2 == -1:
                path = str(event.array1, "utf-8")
            else:
                path = fd2path(event.tgid, event.arg2)
            if DEBUG:    
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "remove attr %s from file %s" % (name, path)))
            modify_object.append("remove attr %s from file %s" % (name, path))
        elif event.arg1 == 1:
            name = str(event.array2, "utf-8")
            path = ""
            if event.arg2 == -1:
                path = str(event.array1, "utf-8")
            else:
                path = fd2path(event.tgid, event.arg2)
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "set attr %s of file %s" % (name, path)))
            modify_object.append("set attr %s of file %s" % (name, path))

    elif event.type == 1023:
        path = fd2path(event.tgid, event.arg1)
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "fs", event.pid, "allocate %d bytes for file %s from %d" % (event.arg3, path, event.arg4)))

        modify_object.append("allocate %d bytes for file %s from %d" % (event.arg3, path, event.arg4))

    elif event.type == -1:
        print("YES")
        
def net_filter(bpf, event):
    comm = str(event.comm, "utf-8")
    global modify_object

    if event.type == 2000:
        check(event)
        if event.ret < 0:
            return
        
        if event.arg4 == -1:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "create socket %d, family %d, protocol %d, type %d" % (event.ret, event.arg1, event.arg2, event.arg3)))
            if event.ret > 0:
                opened_file[event.tgid][event.ret] = {"file_type" : "socket", "family" : event.arg1, "protocol" : event.arg2, "type" : event.type}
                # print(opened_file[event.tgid][event.ret])
        else:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "create socket pair [%d,%d], family %d, protocol %d, type %d" % (event.arg4, event.arg5, event.arg1, event.arg2, event.arg3)))
            if event.arg4 > 0:
                opened_file[event.tgid][event.arg4] = {"file_type" : "socket", "family" : event.arg1, "protocol" : event.arg2, "type" : event.type}
            if event.arg5 > 0:
                opened_file[event.tgid][event.arg5] = {"file_type" : "socket", "family" : event.arg1, "protocol" : event.arg2, "type" : event.type}            
        

    elif event.type == 2001:
        if event.arg2 == socket.AF_INET:
            ip = socket.inet_ntop(socket.AF_INET,struct.pack("i", event.arg3))
            port = socket.ntohs(event.arg4)
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "bind sock %d at %s:%d, ret: %d" % (event.arg1, ip, port, event.ret)))
        elif event.arg2 == socket.AF_UNIX:
            path = str(event.array1, "utf-8")
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "bind sock %d at %s, ret: %d" % (event.arg1, path, event.ret)))
        elif event.arg2 == socket.AF_NETLINK:
            nl_pid = event.arg3
            nl_groups = event.arg4
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "bind sock %d at netlink(nl_pid : %d, nl_groups : %d), ret: %d" % (event.arg1, nl_pid, nl_groups, event.ret)))
            modify_object.append("bind sock %d at netlink(nl_pid : %d, nl_groups : %d), ret: %d" % (event.arg1, nl_pid, nl_groups, event.ret))
        else:
            if DEBUG:
                print("net %d error: family %d not be handled" % (event.type, event.arg2))

    elif event.type == 2002:
        check(event)
        if event.arg2 == socket.AF_INET:
            ip = socket.inet_ntop(socket.AF_INET,struct.pack("i", event.arg3))
            port = socket.ntohs(event.arg4)

            if event.ret == 0 or event.ret == -115:
                opened_file[event.tgid][event.arg1]["address"] = "%s:%d" % (ip, port)

            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "connect sock %d at %s:%d, ret: %d" % (event.arg1, ip, port, event.ret)))
            modify_object.append("connect sock %d at %s:%d, ret: %d" % (event.arg1, ip, port, event.ret))

        elif event.arg2 == socket.AF_UNIX:
            path = str(event.array1, "utf-8")
            
            if event.ret == 0 or event.ret == -115:
                opened_file[event.tgid][event.arg1]["address"] = "%s" % (path)

            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "connect sock %d at %s, ret: %d" % (event.arg1, path, event.ret)))
            if path not in ["/var/run/nscd/socket"]:
                modify_object.append("connect sock %d at %s, ret: %d" % (event.arg1, path, event.ret))

        
        else:
            if DEBUG:
                print("net %d error: family %d not be handled" % (event.type, event.arg2))
            

    elif event.type == 2003:
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "listen at sock %d, queue legnth %d" % (event.arg1, event.arg2)))
  
    elif event.type == 2004:
        if event.arg2 == socket.AF_INET:
            ip = socket.inet_ntop(socket.AF_INET,struct.pack("i", event.arg3))
            port = socket.ntohs(event.arg4)
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "accept sock %d from %s:%d at sock %d" % (event.ret, ip, port, event.arg1)))
            modify_object.append("accept sock %d from %s:%d at sock %d" % (event.ret, ip, port, event.arg1))

        elif event.arg2 == socket.AF_UNIX:
            path = str(event.array1, "utf-8")
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "accept sock %d from %s at sock %d" % (event.ret, path, event.arg1)))
            modify_object.append("accept sock %d from %s at sock %d" % (event.ret, path, event.arg1))

        else:
            if DEBUG:
                print("net %d error: family %d not be handled" % (event.type, event.arg2))

        # if event.ret >= 0:
        #     opened_file[event.tgid][event.ret] = {"type" : "socket"}

    elif event.type == 2005:
        if event.arg2 == 0 or event.arg2 == 2:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "send %d bytes to sock %d" % (event.ret, event.arg1)))
            modify_object.append("send %d bytes to sock %d" % (event.ret, event.arg1))

        elif event.arg2 == 1:
            if event.arg3 == socket.AF_INET:
                ip = socket.inet_ntop(socket.AF_INET,struct.pack("i", event.arg4))
                port = socket.ntohs(event.arg5)
                if event.ret >= 0:
                    if DEBUG:
                        print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "send %d bytes to %s:%s, bind sock %d to %s:%s" % (event.ret, ip, port, event.arg1, ip, port)))
                    modify_object.append("send %d bytes to %s:%s, bind sock %d to %s:%s" % (event.ret, ip, port, event.arg1, ip, port))
                else:
                    if DEBUG:
                        print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "send %d bytes to %s:%s" % (event.ret, ip, port)))
                    modify_object.append("send %d bytes to %s:%s" % (event.ret, ip, port))

            elif event.arg3 == socket.AF_UNIX:
                path = str(event.array1, "utf-8")
                if event.ret >= 0:
                    if DEBUG:
                        print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "send %d bytes to %s, bind sock %d to %s" % (event.ret, event.array1, event.arg1, event.array1)))
                    modify_object.append("send %d bytes to %s, bind sock %d to %s" % (event.ret, event.array1, event.arg1, event.array1))
                else:
                    if DEBUG:
                        print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "send %d bytes to %s" % (event.ret, event.array1)))
                    modify_object.append("send %d bytes to %s" % (event.ret, event.array1))

            elif event.arg3 == socket.AF_NETLINK or event.arg3 == 0:
                if DEBUG:
                    print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "send %d bytes to sock %d" % (event.ret, event.arg1)))
                modify_object.append("send %d bytes to sock %d" % (event.ret, event.arg1))

            else:
                if DEBUG:
                    print("net %d error: family %d not be handled" % (event.type, event.arg3))

        elif event.arg2 == 3:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "send %d segments to sock %d" % (event.ret, event.arg1)))
            modify_object.append("send %d segments to sock %d" % (event.ret, event.arg1))

    elif event.type == 2006:
        if event.arg2 == 0 or event.arg2 == 2:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "recv %d bytes from sock %d" % (event.ret, event.arg1)))
            modify_object.append("recv %d bytes from sock %d" % (event.ret, event.arg1))

        elif event.arg2 == 1:
            if event.arg3 == socket.AF_INET:
                ip = socket.inet_ntop(socket.AF_INET,struct.pack("i", event.arg4))
                port = socket.ntohs(event.arg5)
                if DEBUG:
                    print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "recv %d bytes from %s:%s" % (event.ret, ip, port)))
                modify_object.append("recv %d bytes from %s:%s" % (event.ret, ip, port))

            elif event.arg3 == socket.AF_UNIX:
                path = str(event.array1, "utf-8")
                if DEBUG:
                    print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "recv %d bytes from %s" % (event.ret, event.array1)))
                modify_object.append("recv %d bytes from %s" % (event.ret, event.array1))

            elif event.arg3 == socket.AF_NETLINK or event.arg3 == 0:
                if DEBUG:
                    print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "recv %d bytes from sock %d, addr_len = %d" % (event.ret, event.arg1, event.arg4)))      
                modify_object.append("recv %d bytes from sock %d" % (event.ret, event.arg1))   

            else:
                if DEBUG:
                    print("net %d error: family %d not be handled" % (event.type, event.arg3))

        elif event.arg2 == 3:
            if DEBUG:
                print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "recv %d segments from sock %d" % (event.ret, event.arg1)))
            modify_object.append("recv %d segments from sock %d" % (event.ret, event.arg1))

    elif event.type == 2007:
        if DEBUG:
            print("%-18d %-16s %-5s %-6d %s" % (event.timestamp, comm, "net", event.pid, "shutdown sock %d, how %d" % (event.arg1, event.arg2)))

    elif event.type == -1:  
        print("YES")

def mm_filter(bpf, event):
    if event.type == 0:
        print("%-18d %-5s %-6d %s" % (event.timestamp, "mm", event.pid, "set end of data segment to 0x%x" % (event.long_arg_1)))
        modify_object.append("set end of data segment to 0x%x" % (event.long_arg_1))

    elif event.type == 1:
        if event.long_arg_1 == 0:
            print("%-18d %-5s %-6d %s" % (event.timestamp, "mm", event.pid, "allocate memory %dB" % (event.long_arg_2)))
            modify_object.append("allocate memory %dB" % (event.long_arg_2))

        elif event.long_arg_1 == 1:
            print("%-18d %-5s %-6d %s" % (event.timestamp, "mm", event.pid, "mmap fd %d of length %d" % (event.long_arg_2, event.long_arg_3)))
            modify_object.append("mmap fd %d of length %d" % (event.long_arg_2, event.long_arg_3))

    elif event.type == 2:
        print("%-18d %-5s %-6d %s" % (event.timestamp, "mm", event.pid, "release %dB from 0x%x" % (event.long_arg_2, event.long_arg_1)))
        modify_object.append("release %dB from 0x%x" % (event.long_arg_2, event.long_arg_1))

    elif event.type == -1:
        print("MM YES")

def dev_filter(bpf, event):
    if event.type == 0:
        if event.int_1 == -1:
            print("%-18d %-5s %-6d %s" % (event.timestamp, "dev", event.pid, "set limit for resourse %d" % (event.int_2)))
            modify_object.append("set limit for resourse %d" % (event.int_2))

        else:
            print("%-18d %-5s %-6d %s" % (event.timestamp, "dev", event.pid, "set limit for resourse %d of proc %d" % (event.int_2, event.int_1)))
            modify_object.append("set limit for resourse %d of proc %d" % (event.int_2, event.int_1))

    elif event.type == 1:
        device = str(event.str, "utf-8")
        print("%-18d %-5s %-6d %s" % (event.timestamp, "dev", event.pid, "set disk limit for id %d at device %s" % (event.int_1, device)))
        modify_object.append("set disk limit for id %d at device %s" % (event.int_1, device))

    elif event.type == -1:
        print("dev YES")

import os

def cmd_filter(bpf, event):
    global modify_object
    global input_cmd

    command = str(event.array1, "utf-8")
    if DEBUG:
        print("%-18d %-5s %-6d %s" % (event.timestamp, "rc", event.pid, "input: %s" % (command)))

    if input_cmd != "":
        # print("*" * 20)
        if len(modify_object) == 0:
            print("query command: %s" % input_cmd)
        else:
            print("update command: %s" % input_cmd)
            for i in modify_object:
                print(" " * 4 + i)
            modify_object = []
        # print("*" * 20)
    
    input_cmd = command

