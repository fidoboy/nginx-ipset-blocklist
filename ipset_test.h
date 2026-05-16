#pragma once

#include <stdlib.h>  /* EXIT_SUCCESS, EXIT_FAILURE */

// Return values from the RPC server
#define IPADDR_IN_IPSET      0xf1
#define IPADDR_NOT_IN_IPSET  0xf2

// Maximum ipset name length (must match kernel constant)
#define IP_SET_MAXNAMELEN    32

/**
 * Initialise the ONC RPC client that talks to the local ipset daemon.
 * Call once per worker process (ngx_http_ipset_on_init_process).
 * Returns EXIT_SUCCESS (0) on success, EXIT_FAILURE (1) on error.
 */
extern int init_ipset_test_clnt(void);

/**
 * Query whether `ipaddr` belongs to ipset `setname`.
 *
 * @param setname  NUL-terminated ipset name (max IP_SET_MAXNAMELEN chars)
 * @param af       Address family: AF_INET or AF_INET6
 * @param ipaddr   Pointer to struct sockaddr_in (AF_INET) or
 *                 struct sockaddr_in6 (AF_INET6)
 *
 * @return IPADDR_IN_IPSET     if the address is in the set
 *         IPADDR_NOT_IN_IPSET if the address is not in the set
 *         EXIT_FAILURE        on RPC/communication error
 */
extern int test_ipaddr_in_ipset(char *setname, int af, void *ipaddr);

/**
 * Destroy the RPC client handle.
 * Returns EXIT_SUCCESS if the handle existed, EXIT_FAILURE otherwise.
 */
extern int deinit_ipset_test_clnt(void);
