/* File-operation fixture for the host monitors: one syscall variant per run.
 *
 *   fs_ops OPERATION DIR [--baseline]
 *
 * Setup (also in --baseline): create DIR/a. The operation then renames or
 * deletes it with exactly one syscall, or opens it once:
 *   rename renameat renameat2 unlink unlinkat open openat creat
 * rename/unlink are what glibc's rename()/unlink() issue on x86-64, and what
 * Python's os.rename/os.replace/os.unlink and pathlib use.
 * exec_usr execs /usr/bin/true; exec_dir execs DIR/true (a copy the caller
 * puts there), i.e. a program outside the system directories.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char a[4096], b[4096];
    int fd, rc = -1;

    if (argc < 3) {
        fprintf(stderr, "usage: %s OPERATION DIR [--baseline]\n", argv[0]);
        return 2;
    }
    snprintf(a, sizeof(a), "%s/a", argv[2]);
    snprintf(b, sizeof(b), "%s/b", argv[2]);
    unlink(b);
    fd = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) { perror("setup"); return 1; }
    close(fd);
    if (argc == 4 && !strcmp(argv[3], "--baseline"))
        return 0;

    const char *op = argv[1];
    if (!strcmp(op, "rename"))         rc = syscall(SYS_rename, a, b);
    else if (!strcmp(op, "renameat"))  rc = syscall(SYS_renameat, AT_FDCWD, a, AT_FDCWD, b);
    else if (!strcmp(op, "renameat2")) rc = syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, 0);
    else if (!strcmp(op, "unlink"))    rc = syscall(SYS_unlink, a);
    else if (!strcmp(op, "unlinkat"))  rc = syscall(SYS_unlinkat, AT_FDCWD, a, 0);
    else if (!strcmp(op, "open"))      { rc = syscall(SYS_open, a, O_RDONLY, 0); if (rc >= 0) { close(rc); rc = 0; } }
    else if (!strcmp(op, "openat"))    { rc = syscall(SYS_openat, AT_FDCWD, a, O_RDONLY, 0); if (rc >= 0) { close(rc); rc = 0; } }
    else if (!strcmp(op, "creat"))     { rc = syscall(SYS_creat, b, 0600); if (rc >= 0) { close(rc); rc = 0; } }
    else if (!strcmp(op, "exec_usr") || !strcmp(op, "exec_dir")) {
        char prog[4096];
        char *args[] = { "true", NULL }, *env[] = { NULL };
        if (!strcmp(op, "exec_usr")) snprintf(prog, sizeof(prog), "/usr/bin/true");
        else snprintf(prog, sizeof(prog), "%s/true", argv[2]);
        execve(prog, args, env);
        perror("execve");
        return 1;
    }
    else { fprintf(stderr, "unknown operation %s\n", op); return 2; }
    if (rc != 0) { perror(op); return 1; }
    return 0;
}
