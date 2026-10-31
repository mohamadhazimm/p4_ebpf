#ifndef __MODELMON_H
#define __MODELMON_H

#define MODEL_EVENT_CONNECT 1
#define MODEL_EVENT_OPENAT 2
#define MODEL_EVENT_OPENAT2 3
#define MODEL_EVENT_SENDTO 4
#define MODEL_EVENT_SOCKET 5
#define MODEL_EVENT_WRITE 6
#define MODEL_EVENT_PWRITE64 7
#define MODEL_EVENT_WRITEV 8

struct model_event {
    unsigned int type;
    unsigned long long value;
};

#endif
