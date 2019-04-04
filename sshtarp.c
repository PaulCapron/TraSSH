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

    LISTEN_FD = STDERR_FILENO + 1,  /* server socket, passed by systemd */

    SSH_MSG_KEYXINIT    = 20,  /* code for a SSH key-exchange init message */
    SSH_MSG_KEXDH_REPLY = 32   /* Diffie-Hellman key exchange, from server */
};

static const unsigned char BANNER_AND_KEXINIT[182] = {
    /*
     * The identification string, aka "banner". Appear known-to-be-weak,
     * https://gist.github.com/0x4D31/35ddb0322530414bbb4c3288292749cc
     */
    'S','S','H','-','2','.','0','-',
    'l','i','b','s','s','h','-','0','.','6','.','3','\r','\n',

    /*
     * A valid and innocent "start of key exchange" packet.
     */
    0, 0, 0, 148,      /* packet length  */
    5,                 /* padding length */
    SSH_MSG_KEYXINIT,  /* message type   */
    'e','r','h','a','r','t',':','/','b','i','n','/','c','s','h','\n', /* cook */
    0, 0, 0, 27, 'd','i','f','f','i','e','-','h','e','l','l','m','a','n',
    '-','g','r','o','u','p','1','4','-','s','h','a','1',   /*     key echange */
    0, 0, 0,  7, 's','s','h','-','r','s','a',              /*        host key */
    0, 0, 0, 10, 'a','e','s','1','2','8','-','c','b','c',  /* encryption, c2s */
    0, 0, 0, 10, 'a','e','s','1','2','8','-','c','b','c',  /* encryption, s2c */
    0, 0, 0,  9, 'h','m','a','c','-','s','h','a','1',      /*        MAC, c2s */
    0, 0, 0,  9, 'h','m','a','c','-','s','h','a','1',      /*        MAC, s2c */
    0, 0, 0,  4, 'n','o','n','e',                         /* compression, c2s */
    0, 0, 0,  4, 'n','o','n','e',                         /* compression, s2c */
    0, 0, 0,  0,                                           /*  languages, c2s */
    0, 0, 0,  0,                                           /*  languages, s2c */
    1,                                          /*  first kex packet follows? */
    0, 0, 0, 0,                            /* "reserved for future extension" */
    'e','v','a',':','*',  /* padding, deliciously suspicious like the cookie */

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
utoa(unsigned num, char *dst)
{
    unsigned n;
    size_t len;

    for (n = num, len = 1; n > 9; n /= 10, len++) ;  /* count base 10 */
    n = len - 1;  /* write in reverse */
    do {
        dst[n--] = '0' + (num % 10);
        num /= 10;
    } while (num > 0);
    return len;
}

static ssize_t __attribute__((format(printf, 2, 3)))
dprintf(int fd, const char *fmt, ...)
{
    static char buf[256];
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
            j += utoa(va_arg(args, unsigned), buf + j);
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
    int fd;
    size_t bufsiz;
    struct epoll_event evt;

    fd = accept4(srvfd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
    if (fd == -1) {
        if (errno == EAGAIN)
            return -1;  /* no more queued clients */
        die("accept4");
    }

    bufsiz = sizeof BANNER_AND_KEXINIT;  /* will actually use more */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsiz, sizeof bufsiz) == -1)
        die("setsockopt(SO_RCVBUF)");
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsiz, sizeof bufsiz) == -1)
        die("setsockopt(SO_SNDBUF)");

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

    dprintf(STDOUT_FILENO, "new con, fd %u\n", (unsigned)fd);
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

    if (STDIN_FILENO != LISTEN_FD)
        close(STDIN_FILENO);  /* reuse */

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
                while (welcome_new_client(LISTEN_FD, epfd) != -1) ;
            else
                handle_client(evts[i], junk, sizeof junk / 2);

        if (sleep((nevts < MAX_EVENTS) ? SLEEP_TIME : COMA_TIME) != 0)
            die("sleep");
    }
}
