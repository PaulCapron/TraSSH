/**
 * A SSH trolling daemon that wastes the time of script kiddies.
 *
 * Inspired by <https://github.com/skeeto/endlessh>, arguably better:
 * this tarpit monologues more of the SSH protocol, fooling more bots.
 * It keeps no client state, and it is not dynamically configurable.
 *
 * Linux-only. Delegates to systemd socket setup and sandboxing.
 * No stdio or stdlib use. Static link with <https://www.musl-libc.org/>.
 *
 * For reference, see "The Secure Shell (SSH) Transport Layer Protocol",
 * <https://tools.ietf.org/html/rfc4253> and "The Secure Shell (SSH)
 * Protocol Architecture" <https://tools.ietf.org/html/rfc4251>.
 *
 * @author     Paul <paul@fragara.com>
 * @date       2019
 * @license CC0-1.0 <https://creativecommons.org/publicdomain/zero/1.0/>
 */

#define _GNU_SOURCE  /* accept4 */
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum {
    MAX_CLIENTS      = 512,  /* max number of simultaneously connected peers  */
    WRITES_INTERVAL  =  18,  /* seconds of rest between writes to clients     */
    ACCEPTS_INTERVAL =   5,  /* seconds of rest between accepts of new peers  */

    LISTEN_FD       = STDIN_FILENO,       /* server socket, passed by systemd */
    FIRST_CLIENT_FD = STDERR_FILENO + 1,  /* first free(able) file descriptor */

    END =  0,  /* never allocated / terminating marker in the clients array  */
    RIP = -1,  /* "once allocated, may not be the last occupied slot" marker */

    SSH_MSG_KEXINIT     = 20,  /* code for a SSH key-exchange init message */
    SSH_MSG_KEXDH_REPLY = 31   /* Diffie-Hellman key exchange, from server */
};

static const unsigned char BANNER_AND_KEXINIT[238] = {
    /*
     * The identification string, aka "banner". Appear known-to-be-weak,
     * https://gist.github.com/0x4D31/35ddb0322530414bbb4c3288292749cc
     */
    'S','S','H','-','2','.','0','-',
    'l','i','b','s','s','h','-','0','.','6','.','3','\r','\n',

    /*
     * A valid and innocent "start of key exchange" packet.
     */
    0, 0, 0, 212,      /* packet length  */
    6,                 /* padding length */
    SSH_MSG_KEXINIT,   /* message type   */
    'e','r','h','a','r','t',':','/','b','i','n','/','c','s','h','\n', /* cook */
    0, 0, 0, 27, 'd','i','f','f','i','e','-','h','e','l','l','m','a','n',
    '-','g','r','o','u','p','1','4','-','s','h','a','1',  /*      key echange */
    0, 0, 0, 15, 's','s','h','-','r','s','a',',',
    's','s','h','-','d','s','s',                          /*         host key */
    0, 0, 0, 21, 'a','e','s','2','5','6','-','c','t','r',',',
    'a','e','s','1','2','8','-','c','b','c',              /*  encryption, c2s */
    0, 0, 0, 21, 'a','e','s','2','5','6','-','c','t','r',',',
    'a','e','s','1','2','8','-','c','b','c',              /*  encryption, s2c */
    0, 0, 0, 23, 'h','m','a','c','-','s','h','a','2','-','2','5','6',',',
    'h','m','a','c','-','s','h','a','1',                  /*         MAC, c2s */
    0, 0, 0, 23, 'h','m','a','c','-','s','h','a','2','-','2','5','6',',',
    'h','m','a','c','-','s','h','a','1',                  /*         MAC, s2c */
    0, 0, 0,  4, 'n','o','n','e',                         /* compression, c2s */
    0, 0, 0,  9, 'z','l','i','b',',','n','o','n','e',     /* compression, s2c */
    0, 0, 0,  0,                                          /*   languages, c2s */
    0, 0, 0,  0,                                          /*   languages, s2c */
    1,                                 /* first (guessed) kex packet follows? */
    0, 0, 0, 0,                            /* "reserved for future extension" */
    'e','v','a',':','*',':',  /* padding, delicious like the cookie */
};

static const unsigned char BOGUS_DATA[32] = {  /* junk repeatedly sent */
    0, 0, 0x9c, 0x3c,  /* ~ max packet length allowed by libssh2 (40kB) ;-) */
    12,
    SSH_MSG_KEXDH_REPLY,
    0, 0, 0x9b, 0,     /* "key & certificates" length (keep it plausible)   */
    '1','0','2','9',':','1','0','2','9',':',
    'E','v','a',' ','R','u','h','r','l','a','d','i'
};

static size_t
utoa(unsigned num, unsigned radix, char *dst, size_t dstcapacity)
{
    unsigned n, r;
    size_t len;

    for (n = num, len = 1; n > radix-1; n /= radix, len++) ;  /* count digits */
    if (len > dstcapacity)
        return 0;

    n = len - 1;  /* write in reverse */
    do {
        r = num % radix;
        dst[n--] = (r < 10) ? ('0' + r) : ('a' + r - 10);
        num /= radix;
    } while (num > 0);
    return len;
}

static ssize_t __attribute__((format(printf, 2, 3)))
dprintf(int fd, const char *fmt, ...)  /* light version of stdio dprintf */
{
    char buf[256];
    va_list args;
    unsigned i, j;
    char *s;
    size_t slen;

    va_start(args, fmt);
    for (i = j = 0; fmt[i] != '\0' && j < sizeof buf; i++) {
        if (fmt[i] != '%') {
            buf[j++] = fmt[i];
            continue;
        }
        switch (fmt[++i]) {
        case 'u':
            j += utoa(va_arg(args, unsigned), 10, buf + j, sizeof buf - j);
            break;
        case 'x':
            j += utoa(va_arg(args, unsigned), 16, buf + j, sizeof buf - j);
            break;
        case 's':
            s = va_arg(args, char*);
            slen = strlen(s);
            if (slen <= sizeof buf - j) {
                memcpy(buf + j, s, slen);
                j += slen;
            }
            break;
        default:
            ;  /* not implemented! */
        }
    }
    va_end(args);
    return write(fd, buf, j);
}

static void __attribute__((cold, noreturn))
die(const char *msg)
{
    dprintf(STDERR_FILENO, "%s: %s\n", msg, strerror(errno));
    _exit(2);
}

static time_t
roughmonotime(void)  /* seconds elapsed, roughly, since some arbitrary epoch */
{
    struct timespec t;

    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &t) == -1)
        die("clock_gettime");

    return (t.tv_nsec >= 500000000) ? (t.tv_sec + 1) : t.tv_sec;
}

static void
sleeptill(time_t deadline)
{
    struct timespec t;
    int r;

    t.tv_sec = deadline;
    t.tv_nsec = 0;
    r = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL);
    if (r != 0) {
        errno = r;  /* cannot be EINTR: no signals are handled */
        die("clock_nanosleep");
    }
}

static void
welcome_new_client(int srvfd, int clients[])
{
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int fd;
    unsigned char *ip;

    addrlen = sizeof addr;
    fd = accept4(srvfd, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
    if (fd == -1)
        die("accept4");

    if (write(fd, BANNER_AND_KEXINIT, sizeof BANNER_AND_KEXINIT) < 1) {
        dprintf(STDOUT_FILENO, "could not greet %u: %s\n",
                (unsigned)fd, strerror(errno));
        close(fd);
        return;
    }

    switch (addr.ss_family) {
    case AF_INET:
        ip = (unsigned char *)&((struct sockaddr_in *)&addr)->sin_addr;
        dprintf(STDOUT_FILENO, "new con from %u.%u.%u.%u, fd %u\n",
                ip[0], ip[1], ip[2], ip[3], fd);
        break;
    case AF_INET6:
        ip = (unsigned char *)&((struct sockaddr_in6 *)&addr)->sin6_addr;
        dprintf(STDOUT_FILENO, "new con from %x:%x:%x:%x:%x:%x:%x:%x, fd %u\n",
                (ip[ 0]<<8) + ip[ 1],  (ip[ 2]<<8) + ip[ 3],
                (ip[ 4]<<8) + ip[ 5],  (ip[ 6]<<8) + ip[ 7],
                (ip[ 8]<<8) + ip[ 9],  (ip[10]<<8) + ip[11],
                (ip[12]<<8) + ip[13],  (ip[14]<<8) + ip[15],  fd);
        /* This doesn't shorten the longest run of "0:" to "::", or special-case
           IPv4-mapped addresses. RFC 5952 says these are SHOULD, not MUST.
           And this program is intended for service over IPv4. */
        break;
    default:
        dprintf(STDOUT_FILENO, "new con, fd %u\n", fd);
    }

    if (fd < FIRST_CLIENT_FD || fd >= MAX_CLIENTS - FIRST_CLIENT_FD) {
        errno = EFAULT;
        die("last client fd makes for an out of bounds index");
    }
    clients[fd - FIRST_CLIENT_FD] = fd;
}

static int
handle_clients(int clients[], const void *data, size_t datalen)
{
    int i, writes, fd;

    for (i = writes = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == END) break;
        if (clients[i] == RIP) continue;

        fd = clients[i];
        if (write(fd, data, datalen) == (ssize_t)datalen) {
            writes++;
        } else {
            dprintf(STDOUT_FILENO, "closing fd %u: %s\n", fd, strerror(errno));
            /* errno may just be EWOULDBLOCK, or even 0 in case of short write.
               Slow clients get nuked, by design. */
            close(fd);
            clients[i] = RIP;
        }
    }

    if (writes == MAX_CLIENTS) {  /* full; make some room */
        for (i = 0; i < MAX_CLIENTS; i += (MAX_CLIENTS / 32)) {
            fd = clients[i];
            dprintf(STDOUT_FILENO, "closing fd %u: max clients reached\n", fd);
            close(fd);
            clients[i] = RIP;
        }
    }
    return writes;
}

static void
clean_file_descriptors(void)  /* to ensure no jumps in clients array indexes */
{
    enum { NFDS = MAX_CLIENTS + 3 };
    struct pollfd pfds[NFDS];
    int i;

    for (i = 0; i < NFDS; i++)
        pfds[i].fd = i;

    if (poll(pfds, NFDS, 0) == -1)
        die("poll");

    /* std{in,out,err} must be opened, not allocatable to client sockets: */
    if (pfds[0].revents & POLLNVAL) { errno = EBADF; die("stdin"); }
    if (pfds[1].revents & POLLNVAL) { errno = EBADF; die("stdout"); }
    if (pfds[2].revents & POLLNVAL) { errno = EBADF; die("stderr"); }

    /* On the other hand, fds intended for client sockets must be available: */
    for (i = FIRST_CLIENT_FD; i < NFDS; i++)
        if (!(pfds[i].revents & POLLNVAL)) {
            close(i);
            dprintf(STDERR_FILENO, "warning: closed fd %u "
                    "(intended to be a future client socket)\n", i);
        }
}

int
main()
{
    int clients[MAX_CLIENTS] = { END };
    struct pollfd pfd[1]     = { { LISTEN_FD, POLLIN, 0 } };
    time_t nextwrite         = 0;
    time_t nextaccept        = 0;

    clean_file_descriptors();

    for (;;) {
        int timeout;
        time_t now = roughmonotime();

        if (now >= nextwrite) {
            nextwrite = now + WRITES_INTERVAL;
            if (handle_clients(clients, BOGUS_DATA, sizeof BOGUS_DATA) == 0)
                timeout = -1;  /* no clients; wait for one indefinitely */
            else
                timeout = WRITES_INTERVAL * 1000;
        } else {
            timeout = (nextwrite - now) * 1000;
        }

        if (now >= nextaccept)
            switch(poll(pfd, 1, timeout)) {
            case -1: die("poll");
            case 0: continue;  /* timed out; no need to sleep */
            case 1:
                welcome_new_client(LISTEN_FD, clients);
                nextaccept = roughmonotime() + ACCEPTS_INTERVAL;
            }

        sleeptill((nextaccept < nextwrite) ? nextaccept : nextwrite);
    }
}
