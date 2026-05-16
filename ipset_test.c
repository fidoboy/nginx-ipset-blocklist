#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ipset_test_rpc.h"
#include "ipset_test.h"

// Uncomment to enable verbose debug output to stderr
// #define IPSET_DEBUG

static CLIENT *clnt = NULL;
static const char *rpc_server = "localhost";

int init_ipset_test_clnt(void)
{
    clnt = clnt_create(rpc_server,
                       IPSET_TEST_PROG,
                       IPSET_TEST_VERS,
                       "udp");

    if (clnt == NULL) {
        clnt_pcreateerror(rpc_server);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int test_ipaddr_in_ipset(char *setname, int af, void *ipaddr)
{
    int *ret;
    test_ipaddr_in_ipset_req req;

    if (clnt == NULL) {
        fprintf(stderr, "ipset_test: RPC client not initialised\n");
        return EXIT_FAILURE;
    }

    memset(&req, 0, sizeof(req));
    req.af = af;

    // Copy set name (already validated by the caller to fit in IP_SET_MAXNAMELEN)
    strncpy(req.setname, setname, sizeof(req.setname) - 1);

    if (af == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) ipaddr;
        memcpy(&req.ip4addr.addr, &sin->sin_addr.s_addr, sizeof(req.ip4addr.addr));
    } else if (af == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) ipaddr;
        memcpy(req.ip6addr.addr, sin6->sin6_addr.s6_addr, sizeof(req.ip6addr.addr));
    } else {
        fprintf(stderr, "ipset_test: unsupported address family %d\n", af);
        return EXIT_FAILURE;
    }

#ifdef IPSET_DEBUG
    fprintf(stderr, "[%ld] ipset query: set=%s af=%d addr=",
            (long) time(NULL), req.setname, req.af);
    if (af == AF_INET) {
        const unsigned char *b = (const unsigned char *) &req.ip4addr.addr;
        fprintf(stderr, "%d.%d.%d.%d\n", b[0], b[1], b[2], b[3]);
    } else {
        for (int i = 0; i < 16; i++) {
            fprintf(stderr, "%02x%s", req.ip6addr.addr[i], (i == 15) ? "\n" : ":");
        }
    }
#endif

    ret = test_ipaddr_in_ipset_1(&req, clnt);
    if (ret == NULL) {
        clnt_perror(clnt, rpc_server);
        return EXIT_FAILURE;
    }

#ifdef IPSET_DEBUG
    fprintf(stderr, "[%ld] ipset result: %d\n", (long) time(NULL), *ret);
#endif

    return *ret;
}

int deinit_ipset_test_clnt(void)
{
    if (clnt != NULL) {
        clnt_destroy(clnt);
        clnt = NULL;
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
