/*
 * ipset_test_ping.c
 *
 * Simple health-check utility for ipset_test_server.
 *
 * It contacts rpcbind, resolves the dynamically assigned port for
 * IPSET_TEST_PROG/IPSET_TEST_VERS, then performs a NULLPROC RPC call.
 *
 * Exit status:
 *   0 = server reachable and responding
 *   1 = failure
 */

#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>

#include "ipset_test_rpc.h"

static const char rpc_host[] = "127.0.0.1";
static const char rpc_proto[] = "udp";
static const struct timeval rpc_timeout = { 1, 0 };

static bool_t
xdr_void_compat(XDR *xdrs, ...)
{
    (void) xdrs;
    return TRUE;
}

int
main(void)
{
    CLIENT *clnt;
    enum clnt_stat stat;

    clnt = clnt_create(rpc_host,
                       IPSET_TEST_PROG,
                       IPSET_TEST_VERS,
                       rpc_proto);

    if (clnt == NULL) {
        clnt_pcreateerror("clnt_create");
        return EXIT_FAILURE;
    }

    /* Standard ONC RPC health check */
    stat = clnt_call(clnt,
                     NULLPROC,
                     xdr_void_compat,
                     NULL,
                     xdr_void_compat,
                     NULL,
                     rpc_timeout);

    if (stat != RPC_SUCCESS) {
        clnt_perror(clnt, "NULLPROC");
        clnt_destroy(clnt);
        return EXIT_FAILURE;
    }

    clnt_destroy(clnt);

    return EXIT_SUCCESS;
}
