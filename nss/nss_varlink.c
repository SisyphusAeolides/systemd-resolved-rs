/* Talk to unix:/run/systemd/resolve/io.systemd.Resolve on SHM miss.
 * Production: use proper varlink client or dbus.
 * For landing: connect, send ResolveHostname JSON, parse addresses.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int sr_varlink_resolve_hostname(const char *name,
                                /* out */ char *ip_strs[] , int max,
                                int *n_out)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    strncpy(sa.sun_path, "/run/systemd/resolve/io.systemd.Resolve",
            sizeof sa.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd);
        return -1;
    }
    /* Minimal placeholder — implement varlink call framing */
    (void)name; (void)ip_strs; (void)max;
    *n_out = 0;
    close(fd);
    errno = ENOSYS;
    return -1;
}
