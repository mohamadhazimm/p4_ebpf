#ifndef __FILEMON_H
#define __FILEMON_H

#define EVENT_OPEN    1
#define EVENT_RENAME  2
#define EVENT_UNLINK  3

struct event {
    unsigned int type;
    unsigned int pid;
    char comm[16];
    char path1[256];
    char path2[256];
};

#endif