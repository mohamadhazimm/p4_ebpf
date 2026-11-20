#ifndef __EXECMON_H
#define __EXECMON_H

struct event {
    unsigned int pid;
    char comm[16];
    char filename[256];
};

#endif