/*
 * ipset_test_server.c
 *
 * ONC RPC daemon — answers membership queries for the nginx ipset module.
 * Implements the server side of the RPC interface defined in ipset_test_rpc.x
 *
 * Query method: executes "ipset test <setname> <ip>" directly via exec().
 * This requires the `ipset` utility to be installed and readable by root.
 *
 * Build: see Makefile
 * Run:   ./ipset_test_server   (must run as root or with CAP_NET_ADMIN)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>

#include "ipset_test_rpc.h"
#include "ipset_test.h"

#ifndef IPSET_PATH
#define IPSET_PATH "/usr/sbin/ipset"
#endif

static unsigned g_cache_ttl_sec = 5;
static size_t   g_cache_cap = 256;
static size_t   g_cache_next = 0;
static int g_verbose = 0;

typedef struct {
    int used;
    int af;
    char setname[IP_SET_MAXNAMELEN];
    char ip[INET6_ADDRSTRLEN];
    int result;
    time_t expires_at;
} cache_entry_t;

static cache_entry_t *g_cache = NULL;

/* --------------------------------------------------------------------------
 * Helper: convert raw IPv4 bytes (network order) to dotted-decimal string
 * -------------------------------------------------------------------------- */
static void ip4_to_str(const ip4_addr *addr, char *buf, size_t len)
{
    struct in_addr a;
    a.s_addr = addr->addr;   /* already in network byte order */
    inet_ntop(AF_INET, &a, buf, (socklen_t) len);
}

/* --------------------------------------------------------------------------
 * Helper: convert raw IPv6 bytes to colon-hex string
 * -------------------------------------------------------------------------- */
static void ip6_to_str(const ip6_addr *addr, char *buf, size_t len)
{
    struct in6_addr a;
    memcpy(a.s6_addr, addr->addr, 16);
    inet_ntop(AF_INET6, &a, buf, (socklen_t) len);
}

/* --------------------------------------------------------------------------
 * RPC helper: compatible wrapper for xdr_void
 * -------------------------------------------------------------------------- */
static bool_t
xdr_void_compat(XDR *xdrs, ...)
{
    (void) xdrs;
    return TRUE;
}

static void cleanup_rpc(int sig)
{
    (void)sig;
    syslog(LOG_INFO, "shutting down");
    pmap_unset(IPSET_TEST_PROG, IPSET_TEST_VERS);
    free(g_cache);
    closelog();
    exit(EXIT_SUCCESS);
}

/* --------------------------------------------------------------------------
 * Helper: small TTL cache
 * -------------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-t ttl_seconds] [-n cache_entries] [-v]\n", prog);
}
static int cache_init(size_t cap)
{
    if (cap == 0) {
        cap = 1;
    }

    g_cache = calloc(cap, sizeof(*g_cache));
    if (!g_cache) {
        syslog(LOG_ERR, "calloc(%zu) failed: %s", cap, strerror(errno));
        return 0;
    }

    g_cache_cap = cap;
    g_cache_next = 0;
    return 1;
}

static int cache_lookup(int af, const char *setname, const char *ip, int *out_result)
{
    if (!g_cache || g_cache_ttl_sec == 0) {
        return 0;
    }

    time_t now = time(NULL);

    for (size_t i = 0; i < g_cache_cap; i++) {
        cache_entry_t *e = &g_cache[i];

        if (!e->used) {
            continue;
        }

        if (e->expires_at <= now) {
            e->used = 0;
            continue;
        }

        if (e->af == af &&
            strcmp(e->setname, setname) == 0 &&
            strcmp(e->ip, ip) == 0) {

            *out_result = e->result;
            return 1;
        }
    }

    return 0;
}

static void cache_store(int af, const char *setname, const char *ip, int result)
{
    if (!g_cache || g_cache_ttl_sec == 0) {
        return;
    }

    time_t now = time(NULL);
    size_t slot = g_cache_next++ % g_cache_cap;
    cache_entry_t *e = &g_cache[slot];

    e->used = 1;
    e->af = af;
    snprintf(e->setname, sizeof(e->setname), "%s", setname);
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->result = result;
    e->expires_at = now + (time_t)g_cache_ttl_sec;
}

/* --------------------------------------------------------------------------
 * Core: query ipset via the CLI tool
 *
 * Returns:
 *   IPADDR_IN_IPSET      if ip is a member of setname
 *   IPADDR_NOT_IN_IPSET  if it is not
 *   EXIT_FAILURE         on any error (ipset not found, set doesn't exist …)
 * -------------------------------------------------------------------------- */
static int query_ipset(const char *setname, const char *ip_str)
{
    pid_t pid;
    int status;

    pid = fork();

    if (pid < 0) {
        syslog(LOG_ERR,
               "ipset_test_server: fork() failed: %s",
               strerror(errno));
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        if (g_verbose) {
            execl(IPSET_PATH,
                  "ipset",
                  "test",
                  setname,
                  ip_str,
                  (char *)NULL);
        } else {
            execl(IPSET_PATH,
                  "ipset",
                  "-q",
                  "test",
                  setname,
                  ip_str,
                  (char *)NULL);
        }

        syslog(LOG_ERR,
           "ipset_test_server: exec(%s) failed: %s",
           IPSET_PATH,
           strerror(errno));

        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0) {
        syslog(LOG_ERR,
               "ipset_test_server: waitpid() failed: %s",
               strerror(errno));
        return EXIT_FAILURE;
    }

    if (WIFEXITED(status)) {

        int code = WEXITSTATUS(status);

        if (code == 0) {
            return IPADDR_IN_IPSET;
        }

        if (code == 1) {
            return IPADDR_NOT_IN_IPSET;
        }

        syslog(LOG_ERR,
               "ipset_test_server: ipset exited with code %d",
               code);

        return EXIT_FAILURE;
    }

    syslog(LOG_ERR,
           "ipset_test_server: ipset terminated abnormally");

    return EXIT_FAILURE;
}

/* --------------------------------------------------------------------------
 * RPC procedure implementation — called by the rpcgen-generated dispatcher
 * -------------------------------------------------------------------------- */
int *
test_ipaddr_in_ipset_1_svc(test_ipaddr_in_ipset_req *argp, struct svc_req *rqstp)
{
    (void)rqstp;
    static int result;
    char ip_str[INET6_ADDRSTRLEN];
    char setname[IP_SET_MAXNAMELEN];

    /* Sanitise set name: ensure NUL-termination */
    memcpy(setname, argp->setname, IP_SET_MAXNAMELEN - 1);
    setname[IP_SET_MAXNAMELEN - 1] = '\0';

    if (argp->af == AF_INET) {
        ip4_to_str(&argp->ip4addr, ip_str, sizeof(ip_str));
    } else if (argp->af == AF_INET6) {
        ip6_to_str(&argp->ip6addr, ip_str, sizeof(ip_str));
    } else {
        syslog(LOG_WARNING, "ipset_test_server: unknown address family %d", argp->af);
        result = EXIT_FAILURE;
        return &result;
    }

    if (cache_lookup(argp->af, setname, ip_str, &result)) {
        if (g_verbose) {
            syslog(LOG_INFO, "cache hit: af=%d set=%s ip=%s -> %d", argp->af, setname, ip_str, result);
        }
        return &result;
    }

    result = query_ipset(setname, ip_str);
    if (g_verbose) {
        syslog(LOG_INFO, "ipset test: af=%d set=%s ip=%s -> %d", argp->af, setname, ip_str, result);
    }
    if (result == IPADDR_IN_IPSET || result == IPADDR_NOT_IN_IPSET) {
        cache_store(argp->af, setname, ip_str, result);
    }

    return &result;
}

/* --------------------------------------------------------------------------
 * freeresult — nothing to free (we return a pointer to a static int)
 * -------------------------------------------------------------------------- */
int
ipset_test_prog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
    (void) transp;
    (void) xdr_result;
    (void) result;
    return 1;
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

/*
 * The rpcgen-generated server registration code is declared in the header.
 * We need to implement the registration ourselves here (rpcgen would normally
 * produce ipset_test_rpc_svc.c, but we don't have it, so we do it manually).
 */
static void ipset_test_prog_1(struct svc_req *rqstp, SVCXPRT *transp);

int main(int argc, char **argv)
{
    SVCXPRT *transp;
    int udp_sock;
    struct sockaddr_in udp_addr;
    int tcp_sock = -1;
    struct sockaddr_in tcp_addr;
    int opt = 1;
    int c;

    while ((c = getopt(argc, argv, "t:n:vh")) != -1) {
        switch (c) {
        case 't':
        {
            char *end1;
            unsigned long ttl = strtoul(optarg, &end1, 10);
            if (*end1 != '\0') {
                fprintf(stderr, "Invalid TTL. It should be a number.\n");
                exit(EXIT_FAILURE);
            }
            if (ttl > 3600) {
                fprintf(stderr, "TTL too large. Valid values are 0 (disabled) to 3600.\n");
                exit(EXIT_FAILURE);
            }
            g_cache_ttl_sec = (unsigned)ttl;
            break;
        }
        case 'n':
        {
            char *end2;
            unsigned long entries = strtoul(optarg, &end2, 10);
            if (*end2 != '\0') {
                fprintf(stderr, "Invalid cache size. It should be a number.\n");
                exit(EXIT_FAILURE);
            }

            if (entries == 0 || entries > 65536) {
                fprintf(stderr, "Invalid cache size. Valid values between 1 and 65536.\n");
                exit(EXIT_FAILURE);
            }
            g_cache_cap = (size_t)entries;
            break;
        }
        case 'v':
            g_verbose = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    openlog("ipset_test_server", LOG_PID | LOG_CONS, LOG_DAEMON);
    
    if (g_cache_ttl_sec != 0) {
        if (!cache_init(g_cache_cap)) {
            closelog();
            exit(EXIT_FAILURE);
        }
    }
    
    signal(SIGTERM, cleanup_rpc);
    signal(SIGINT, cleanup_rpc);
    syslog(LOG_INFO, "starting up...");
    if (g_verbose) {
        syslog(LOG_INFO, "> verbose logging enabled");
    }
    if (g_cache_ttl_sec == 0) {
        syslog(LOG_INFO, "> cache disabled");
    } else {
        syslog(LOG_INFO, "> cache enabled: ttl=%u sec entries=%zu", g_cache_ttl_sec, g_cache_cap);
    }
    
    /* Unregister any stale registration from a previous run */
    pmap_unset(IPSET_TEST_PROG, IPSET_TEST_VERS);

    /* Register over UDP */
    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (udp_sock < 0) {
        syslog(LOG_ERR, "cannot create UDP socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    memset(&udp_addr, 0, sizeof(udp_addr));
    
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    udp_addr.sin_port = 0;
    
    if (bind(udp_sock,
             (struct sockaddr *)&udp_addr,
             sizeof(udp_addr)) < 0) {
    
        syslog(LOG_ERR, "cannot bind UDP localhost socket: %s",
               strerror(errno));
    
        close(udp_sock);
        exit(EXIT_FAILURE);
    }
    
    transp = svcudp_create(udp_sock);
    if (transp == NULL) {
        syslog(LOG_ERR, "cannot create UDP service");
        exit(EXIT_FAILURE);
    }
    if (!svc_register(transp, IPSET_TEST_PROG, IPSET_TEST_VERS,
                      ipset_test_prog_1, IPPROTO_UDP)) {
        syslog(LOG_ERR, "cannot register UDP service");
        exit(EXIT_FAILURE);
    }

    /* Register over TCP as well (optional but useful for high-load setups) */
    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if (tcp_sock < 0) {
        syslog(LOG_ERR, "cannot create TCP socket: %s",
               strerror(errno));
    } else {
        memset(&tcp_addr, 0, sizeof(tcp_addr));
    
        tcp_addr.sin_family = AF_INET;
        tcp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        tcp_addr.sin_port = 0;
    
        setsockopt(tcp_sock,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &opt,
                   sizeof(opt));
        
        if (bind(tcp_sock,
                 (struct sockaddr *)&tcp_addr,
                 sizeof(tcp_addr)) < 0) {
    
            syslog(LOG_ERR,
                   "cannot bind TCP localhost socket: %s",
                   strerror(errno));
    
            close(tcp_sock);
            tcp_sock = -1;
        } else if (listen(tcp_sock, SOMAXCONN) < 0) {
            syslog(LOG_ERR,
                   "cannot listen TCP socket: %s",
                   strerror(errno));
        
            close(tcp_sock);
            tcp_sock = -1;
        }
    }
    
    if (tcp_sock >= 0)
        transp = svctcp_create(tcp_sock, 0, 0);
    else
        transp = NULL;
    if (transp == NULL) {
        syslog(LOG_WARNING, "cannot create TCP service (UDP-only mode)");
    } else if (!svc_register(transp, IPSET_TEST_PROG, IPSET_TEST_VERS,
                              ipset_test_prog_1, IPPROTO_TCP)) {
        syslog(LOG_WARNING, "cannot register TCP service (UDP-only mode)");
    }

    syslog(LOG_INFO, "ready, listening for requests (prog=0x%x vers=%u)",
           IPSET_TEST_PROG, IPSET_TEST_VERS);

    svc_run();   /* never returns under normal operation */

    syslog(LOG_ERR, "svc_run() returned — this should not happen");
    exit(EXIT_FAILURE);
}

/* --------------------------------------------------------------------------
 * RPC dispatcher (what rpcgen would normally generate in *_svc.c)
 * -------------------------------------------------------------------------- */
static void
ipset_test_prog_1(struct svc_req *rqstp, SVCXPRT *transp)
{
    union {
        test_ipaddr_in_ipset_req test_ipaddr_in_ipset_1_arg;
    } argument;

    char    *result;
    xdrproc_t xdr_argument, xdr_result;
    char    *(*local)(char *, struct svc_req *);

    switch (rqstp->rq_proc) {

    case NULLPROC:
        svc_sendreply(transp, xdr_void_compat, NULL);
        return;

    case TEST_IPADDR_IN_IPSET:
        xdr_argument = (xdrproc_t) xdr_test_ipaddr_in_ipset_req;
        xdr_result   = (xdrproc_t) xdr_int;
        local        = (char *(*)(char *, struct svc_req *))
                           test_ipaddr_in_ipset_1_svc;
        break;

    default:
        svcerr_noproc(transp);
        return;
    }

    memset(&argument, 0, sizeof(argument));

    if (!svc_getargs(transp, xdr_argument, (caddr_t) &argument)) {
        svcerr_decode(transp);
        return;
    }

    result = (*local)((char *) &argument, rqstp);

    if (result != NULL &&
        !svc_sendreply(transp, xdr_result, result)) {
        svcerr_systemerr(transp);
    }

    if (!svc_freeargs(transp, xdr_argument, (caddr_t) &argument)) {
        syslog(LOG_ERR, "unable to free arguments");
    }
}
