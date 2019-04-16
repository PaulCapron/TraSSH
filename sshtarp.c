/**
 * A SSH trolling daemon that wastes the time of script kiddies.
 *
 * Inspired by <https://github.com/skeeto/endlessh>, arguably better:
 * this tarpit monologues more of the SSH protocol, fooling more bots.
 * It keeps no client state, and it is not dynamically configurable.
 *
 * Linux-only (epoll). Delegates to systemd socket setup and sandboxing.
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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>  /* strerror */
#include <unistd.h>

enum {
    MAX_EVENTS = 512,  /* max number of events/fds per epoll run */
    SLEEP_TIME =   9,  /* seconds of rest between epoll runs     */
    COMA_TIME  = SLEEP_TIME * 3,  /* rest if max events reached  */

    LISTEN_FD = STDIN_FILENO,  /* server socket, passed by systemd */

    SSH_MSG_KEXINIT     = 20,  /* code for a SSH key-exchange init message */
    SSH_MSG_KEXDH_REPLY = 31   /* Diffie-Hellman key exchange, from server */
};

static const unsigned char BANNER_AND_KEXINIT[246] = {
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
    0,                                 /* first (guessed) kex packet follows? */
    0, 0, 0, 0,                            /* "reserved for future extension" */
    'e','v','a',':','*',':',  /* padding, delicious like the cookie */

    /*
     * Finally, the start of a "key exchange, step 2, from server" message.
     * The rest of this "message" will be random bytes, sent in handle_client.
     * But most clients realize it is invalid only after full reception!
     */
    0, 0, 0x7f, 0xfc,  /* clients MUST be able to handle at least ~32k */
    4,                 /* minimum bytes of padding */
    SSH_MSG_KEXDH_REPLY,
    0, 0,  /* high bytes of "key & certificates" length (keep it plausible) */
};

static void
scramble(unsigned long x[4])  /* xoshiro256, http://xoshiro.di.unimi.it */
{
     unsigned long t = x[1] << 17;

     x[2] ^= x[0];  x[3] ^= x[1];  x[1] ^= x[2];  x[0] ^= x[3];
     x[2] ^= t;
     x[3] = (x[3] << 45) | (x[3] >> (64 - 45));  /* rotl 45 */
}

static size_t
utoa(unsigned num, char *dst, unsigned radix)  /* does not null-terminate dst */
{
    unsigned n, r;
    size_t len;

    for (n = num, len = 1; n > radix-1; n /= radix, len++) ;  /* count digits */
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
    int i, j;
    char *s;

    va_start(args, fmt);
    for (i = j = 0; fmt[i] != '\0'; i++) {
        if (fmt[i] != '%') {
            buf[j++] = fmt[i];
            continue;
        }
        switch (fmt[++i]) {
        case 'u':
            j += utoa(va_arg(args, unsigned), buf + j,  10);
            break;
        case 'x':
            j += utoa(va_arg(args, unsigned), buf + j,  16);
            break;
        case 's':
            s = va_arg(args, char*);
            while (*s != '\0') buf[j++] = *s++;
            break;
        default:
            ;  /* not implemented! */
        }
    }
    va_end(args);
    return write(fd, buf, j);
}

static void __attribute__((cold))
die(const char *msg)
{
    dprintf(STDERR_FILENO, "%s: %s\n", msg, strerror(errno));
    _exit(2);
}

static int
welcome_new_client(int srvfd, int epollfd)
{
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int fd;
    struct epoll_event evt;
    unsigned char *ip;

    addrlen = sizeof addr;
    fd = accept4(srvfd, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
    if (fd == -1)
        die("accept4");

    if (write(fd, BANNER_AND_KEXINIT, sizeof BANNER_AND_KEXINIT) < 1) {
        dprintf(STDOUT_FILENO, "could not greet %u: %s\n",
                (unsigned)fd, strerror(errno));
        close(fd);
        return 0;  /* not really welcomed */
    }

    evt.events = EPOLLOUT;
    evt.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &evt) == -1)
        die("epoll_clt");

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
    return 1;
}

static void
handle_client(struct epoll_event evt, const void *data, size_t datalen)
{
    char *reason;
    ssize_t written;
    int fd = evt.data.fd;

    if (evt.events & EPOLLHUP) { reason = "peer closed"; goto close; }
    if (evt.events & EPOLLERR) { reason = "epoll error"; goto close; }

    written = write(fd, data, datalen);
    if (written == -1) {
        reason = strerror(errno);
        goto close;
    } else if ((size_t)written < datalen) {
        reason = "short write";
        goto close;
    }
    return;
 close:
    dprintf(STDOUT_FILENO, "closing fd %u: %s\n", (unsigned)fd, reason);
    close(fd);
}

int
main()
{
    int epfd, nevts, i;
    struct epoll_event evt, evts[MAX_EVENTS];
    unsigned long junk[4] = { 0xDeadBeefFeed5eed, 0xBa0bab, 0xCafeCaCa0, 421 };

    junk[2] += getuid();
    junk[3] *= getpid();

    epfd = epoll_create1(EPOLL_CLOEXEC);  /* safety close-on-exec */
    if (epfd == -1)
        die("epoll_create1");

    evt.events = EPOLLIN;
    evt.data.fd = LISTEN_FD;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, LISTEN_FD, &evt) == -1)
        die("epoll_ctl(LISTEN_FD)");

    for (;;) {
        nevts = epoll_wait(epfd, evts, MAX_EVENTS, -1);
        if (nevts == -1)
            die("epoll_wait");

        scramble(junk);
        for (i = 0; i < nevts; i++)
            if (evts[i].data.fd == LISTEN_FD)
                welcome_new_client(LISTEN_FD, epfd);
            else
                handle_client(evts[i], junk, sizeof junk / 2);

        if (sleep((nevts < MAX_EVENTS) ? SLEEP_TIME : COMA_TIME) != 0)
            die("sleep");
    }
}
