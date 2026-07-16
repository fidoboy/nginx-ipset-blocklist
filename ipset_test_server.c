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

#include "ipset_test_rpc.h"
#include "ipset_test.h"

#ifndef IPSET_PATH
#define IPSET_PATH "/usr/sbin/ipset"
#endif

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
        execl(IPSET_PATH,
              "ipset",
              "test",
              setname,
              ip_str,
              (char *)NULL);

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
            syslog(LOG_DEBUG,
                   "ipset_test_server: %s IN %s",
                   ip_str,
                   setname);

            return IPADDR_IN_IPSET;
        }

        if (code == 1) {
            syslog(LOG_DEBUG,
                   "ipset_test_server: %s NOT in %s",
                   ip_str,
                   setname);

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

    result = query_ipset(setname, ip_str);
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
    
    openlog("ipset_test_server", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "starting up");

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
        svc_sendreply(transp, (xdrproc_t) xdr_void, NULL);
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
