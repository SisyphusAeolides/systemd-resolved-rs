/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "native.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t reload_requested = 0;

static void handle_signal(int signal_number) {
    if (signal_number == SIGHUP) {
        reload_requested = 1;
    } else {
        stop_requested = 1;
    }
}

int resolved_install_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;

    if (sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0) {
        return -errno;
    }
    return 0;
}

int resolved_take_reload(void) {
    const int value = reload_requested != 0;
    reload_requested = 0;
    return value;
}

int resolved_should_stop(void) {
    return stop_requested != 0;
}

int resolved_listen_fds(void) {
    const char *pid_text = getenv("LISTEN_PID");
    const char *fds_text = getenv("LISTEN_FDS");
    char *end = NULL;
    unsigned long pid_value;
    unsigned long fds_value;

    if (pid_text == NULL || fds_text == NULL) {
        return 0;
    }

    errno = 0;
    pid_value = strtoul(pid_text, &end, 10);
    if (errno != 0 || end == pid_text || *end != '\0' || pid_value != (unsigned long)getpid()) {
        return 0;
    }

    errno = 0;
    fds_value = strtoul(fds_text, &end, 10);
    if (errno != 0 || end == fds_text || *end != '\0' || fds_value > INT32_MAX) {
        return -EINVAL;
    }

    unsetenv("LISTEN_PID");
    unsetenv("LISTEN_FDS");
    unsetenv("LISTEN_FDNAMES");
    return (int)fds_value;
}

int resolved_notify(const char *state) {
    const char *socket_path = getenv("NOTIFY_SOCKET");
    struct sockaddr_un address;
    size_t path_length;
    socklen_t address_length;
    int fd;
    int result;

    if (state == NULL) {
        return -EINVAL;
    }
    if (socket_path == NULL || socket_path[0] == '\0') {
        return 0;
    }

    path_length = strlen(socket_path);
    if (path_length >= sizeof(address.sun_path)) {
        return -ENAMETOOLONG;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, path_length + 1U);
    if (address.sun_path[0] == '@') {
        address.sun_path[0] = '\0';
    }
    address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1U);

    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -errno;
    }

    result = sendto(fd, state, strlen(state), MSG_NOSIGNAL,
                    (const struct sockaddr *)&address, address_length);
    if (result < 0) {
        result = -errno;
    } else {
        result = 1;
    }
    (void)close(fd);
    return result;
}

int resolved_peer_credentials(int fd, uint32_t *pid, uint32_t *uid, uint32_t *gid) {
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (pid == NULL || uid == NULL || gid == NULL) {
        return -EINVAL;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0) {
        return -errno;
    }
    if (length != sizeof(credentials)) {
        return -EIO;
    }

    *pid = (uint32_t)credentials.pid;
    *uid = (uint32_t)credentials.uid;
    *gid = (uint32_t)credentials.gid;
    return 0;
}
