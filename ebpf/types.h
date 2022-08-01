#ifndef TYPES_H
#define TYPES_H

#include <uapi/linux/ptrace.h>

#define FILE_PATH_LEN 64

#define NR_DEBUG -1

#define NR_IPC_KILL 0
#define NR_IPC_EXIT 1
#define NR_IPC_FORK 2
#define NR_IPC_READ 3
#define NR_IPC_WRITE 4

#define NR_FS_CREATE 1000
#define NR_FS_SOFT_LINK 1001
#define NR_FS_HARD_LINK 1002
#define NR_FS_UNLINK 1003
#define NR_FS_MKDIR 1004
#define NR_FS_RMDIR 1005
#define NR_FS_RENAME 1006
#define NR_FS_OPEN 1007
#define NR_FS_READ 1008
#define NR_FS_WRITE 1009
#define NR_FS_CHDIR 1010
#define NR_FS_DUP2 1011
#define NR_FS_FCNTL 1012
#define NR_FS_CHMOD 1013
#define NR_FS_CHOWN 1014
#define NR_FS_CLOSE 1015
#define NR_FS_SYNC 1016
#define NR_FS_TRUNCATE 1017
#define NR_FS_MKNOD 1018
#define NR_FS_PIPE 1019
#define NR_FS_UTIME 1020
#define NR_FS_SENDFILE 1021
#define NR_FS_XATTR 1022
#define NR_FS_FALLOCATE 1023

#define NR_NET_CREATE_SOCKET 2000
#define NR_NET_BIND 2001
#define NR_NET_CONNECT 2002
#define NR_NET_LISTEN 2003
#define NR_NET_ACCEPT 2004
#define NR_NET_SENDMSG 2005
#define NR_NET_RECVMSG 2006
#define NR_NET_SHUTDOWN 2007

#define NR_MM_BRK 3000
#define NR_MM_MMAP 3001
#define NR_MM_UNMAP 3002

#define NR_DEV_LIMIT 3000
#define NR_DEV_QUOTA 3001

#define NR_UPROBE_CMD 4000

BPF_RINGBUF_OUTPUT(events, 2048);

struct general_surface_t 
{
    int pid;
    u64 timestamp;
    int type;
    int ret;
    char comm[16];
    int tgid;
    
    int arg1;
    int arg2;
    int arg3;
    int arg4;
    int arg5;

    char array1[128];
    char array2[128];

};


#endif
