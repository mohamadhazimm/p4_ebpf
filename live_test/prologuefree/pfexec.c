/* pfexec CGROUP [-o FILE] PROG ARGS...
 *
 * Starts PROG so that a monitor filtering on CGROUP sees nothing before PROG's own first system call
 * after its exec: the startup-free host rows of live_test/prologuefree (RUNBOOK 19.5.6: drop the root's
 * calls before its exec success). pfexec itself runs outside CGROUP. Its child asks to be traced and
 * execs PROG; a successful execve stops the child with SIGTRAP before PROG's first instruction; pfexec
 * then writes the child's PID into CGROUP/cgroup.procs, detaches (the SIGTRAP is discarded) and waits.
 * pfexec exits like PROG: with its code, or by the signal that ended it. -o FILE opens FILE as stdout
 * first (the dataset runner redirected stdout in the parent, outside the trace).
 * PROG is looked up in PATH by execvp before the exec success, so failed attempts are not counted.
 *
 * Build: gcc -O2 -Wall -static -o pfexec pfexec.c (run as root, like the collector). How PC1 used it
 * with hybrid_collector.py, unchanged: PC1.md, "Results, part 3".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t child;

static void forward(int sig) { if (child > 0) kill(child, sig); }

int main(int argc, char **argv)
{
	int argi = 2, st, fd;
	char path[4096], buf[32];

	if (argc < 3) {
		fprintf(stderr, "usage: pfexec CGROUP [-o FILE] PROG ARGS...\n");
		return 2;
	}
	if (!strcmp(argv[2], "-o")) {
		if (argc < 5) return 2;
		fd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0 || dup2(fd, 1) < 0) { perror("pfexec: -o"); return 3; }
		close(fd);
		argi = 4;
	}
	snprintf(path, sizeof(path), "%s/cgroup.procs", argv[1]);
	child = fork();
	if (child < 0) { perror("pfexec: fork"); return 4; }
	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) _exit(126);
		execvp(argv[argi], argv + argi);
		_exit(127);
	}
	if (waitpid(child, &st, 0) < 0) { perror("pfexec: waitpid"); return 5; }
	if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP) {
		fprintf(stderr, "pfexec: %s did not start (status 0x%x)\n", argv[argi], st);
		return WIFEXITED(st) ? WEXITSTATUS(st) : 127;
	}
	fd = open(path, O_WRONLY);
	snprintf(buf, sizeof(buf), "%d\n", (int)child);
	if (fd < 0 || write(fd, buf, strlen(buf)) < 0) {
		perror("pfexec: joining the cgroup");
		kill(child, SIGKILL);
		return 6;
	}
	close(fd);
	if (ptrace(PTRACE_DETACH, child, 0, 0) < 0) { perror("pfexec: detach"); kill(child, SIGKILL); return 7; }
	/* the collector stops a run with SIGTERM to the process group, which reaches both; forward the
	 * catchable ones sent to pfexec alone */
	signal(SIGINT, forward);
	signal(SIGHUP, forward);
	for (;;) {
		if (waitpid(child, &st, 0) < 0) {
			if (errno == EINTR) continue;
			perror("pfexec: waitpid");
			return 5;
		}
		if (WIFEXITED(st)) return WEXITSTATUS(st);
		if (WIFSIGNALED(st)) {
			signal(WTERMSIG(st), SIG_DFL);
			kill(getpid(), WTERMSIG(st));
			return 128 + WTERMSIG(st);
		}
	}
}
