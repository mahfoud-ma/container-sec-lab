#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    const char *ns_paths[] = {
        "/proc/1/ns/mnt",
        "/proc/1/ns/uts",
        "/proc/1/ns/ipc",
        "/proc/1/ns/net",
        NULL
    };

    for (int i = 0; ns_paths[i]; i++) {
        int fd = open(ns_paths[i], O_RDONLY);
        if (fd < 0) { perror(ns_paths[i]); continue; }
        if (setns(fd, 0) < 0) { perror("setns"); close(fd); continue; }
        close(fd);
        printf("Joined: %s\n", ns_paths[i]);
    }

    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0)
        printf("Hostname: %s\n", buf);

    return 0;
}
