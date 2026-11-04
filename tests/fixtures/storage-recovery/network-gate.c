/* Disposable network-lab launch barrier. No network syscalls or shell. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t stopped = 0;
static void stop(int sig) { (void)sig; stopped = 1; }
int main(int argc, char **argv) {
    if (argc < 3 || (strcmp(argv[2], "--hold") && strcmp(argv[2], "/usr/local/bin/weed"))) return 64;
    signal(SIGTERM, stop); signal(SIGINT, stop);
    struct timespec pause = {0, 100000000};
    for (int i = 0; i < 1800 && !stopped; i++) {
        int fd = open(argv[1], O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) {
            struct stat st; char value[7];
            int valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 6
                && read(fd, value, sizeof(value)) == 6 && !memcmp(value, "READY\n", 6);
            close(fd);
            if (!valid) return 65;
            puts("NETWORK_GATE_RELEASED"); fflush(stdout);
            if (!strcmp(argv[2], "--hold")) {
                for (int j = 0; j < 9000 && !stopped; j++) nanosleep(&pause, NULL);
                return stopped ? 0 : 124;
            }
            execv(argv[2], &argv[2]); return 126;
        }
        nanosleep(&pause, NULL);
    }
    return stopped ? 0 : 124;
}
