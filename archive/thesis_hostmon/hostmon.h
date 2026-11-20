#ifndef __HOSTMON_H
#define __HOSTMON_H

#define EVENT_EXEC     1
#define EVENT_OPEN     2
#define EVENT_RENAME   3
#define EVENT_UNLINK   4
#define EVENT_CONNECT  5
#define EVENT_SYSCALL  6

#define PATH_LEN 256

struct event {
    unsigned int type;
    unsigned int pid;
    char comm[16];

    char path1[PATH_LEN];
    char path2[PATH_LEN];

    unsigned int addr;      /* IPv4 address, network byte order */
    unsigned short port;    /* destination port, network byte order */

    unsigned int syscall_id; /* valid when type == EVENT_SYSCALL */
};

#endif