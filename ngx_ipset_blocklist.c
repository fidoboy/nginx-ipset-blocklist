//
// Nginx HTTP ipset blacklist/whitelist access module
// Created by kraloveckey/fidoboy
// Features: location-level directives, simultaneous blacklist+whitelist,
//          multiple ipset entries per context, additive directives,
//          single-name syntax, proper merge logic, improved logging/errors,
//          configurable check order via ipset_priority
//
// Directives (usable in http{}, server{}, location{}):
//
//   blacklist "setname";       # same ipset for IPv4 and IPv6
//
//   blacklist "setname4" "setname6";       # separate ipsets per AF
//
//   blacklist "setname4" "setname6";
//   blacklist "setname4b" "setname6b";       # multiple blacklist directives are additive within the same context
//
//   blacklist off;       # disable blacklist at this level
//
//   whitelist "setname";
//   whitelist "setname4" "setname6";       # multiple whitelist directives are additive within the same context
//
//   whitelist off;
//
//   ipset_priority blacklist;             # check blacklist first (default)
//   ipset_priority whitelist;              # check whitelist first
//
// Logic:
//   - blacklist: deny (444) if IP is IN any configured blacklist set
//   - whitelist: deny (444) if IP is NOT IN any configured whitelist set
//   - Multiple blacklist/whitelist directives are evaluated cumulatively
//   - Both may be active simultaneously; order controlled by ipset_priority
//   - ipset_priority blacklist (default): deny overrides allow
//     use when a blacklisted IP should be blocked even if it is also whitelisted
//   - ipset_priority whitelist: allow overrides deny
//     use when a whitelisted IP should always pass even if it is also blacklisted
//   - On RPC error: log a warning and pass the request (fail-open)
//   - "off" explicitly disables that list for this context (not inherited from parent)
//   - ipset_priority is inherited from parent context like blacklist/whitelist
//
 
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/socket.h>
 
#include "ipset_test.h"
 
// Values for the blacklist/whitelist state fields
#define IPSET_LIST_UNSET  0   // not configured at this level — inherit from parent
#define IPSET_LIST_OFF    1   // explicitly disabled with "off"
#define IPSET_LIST_ON     2   // active
 
// Values for the priority field
#define IPSET_PRIORITY_UNSET      0   // not configured — inherit from parent
#define IPSET_PRIORITY_BLACKLIST  1   // check blacklist first (default)
#define IPSET_PRIORITY_WHITELIST  2   // check whitelist first

#define NGX_HTTP_CLOSE_REQUEST 444
#define NGX_IPSET_MAX_SETS 16

typedef struct {

    ngx_uint_t  blacklist;   // IPSET_LIST_UNSET / OFF / ON

    // Multiple blacklist sets per address family.
    // Each blacklist directive adds one entry.
    char        blacklist_set4[NGX_IPSET_MAX_SETS][IP_SET_MAXNAMELEN];
    char        blacklist_set6[NGX_IPSET_MAX_SETS][IP_SET_MAXNAMELEN];

    ngx_uint_t  blacklist_set4_count;
    ngx_uint_t  blacklist_set6_count;


    ngx_uint_t  whitelist;   // IPSET_LIST_UNSET / OFF / ON

    // Multiple whitelist sets per address family.
    // Each whitelist directive adds one entry.
    char        whitelist_set4[NGX_IPSET_MAX_SETS][IP_SET_MAXNAMELEN];
    char        whitelist_set6[NGX_IPSET_MAX_SETS][IP_SET_MAXNAMELEN];

    ngx_uint_t  whitelist_set4_count;
    ngx_uint_t  whitelist_set6_count;


    ngx_uint_t  priority;   // IPSET_PRIORITY_UNSET / BLACKLIST / WHITELIST

} ngx_ipset_access_loc_conf_t;
 
// Forward declarations
static char     *ngx_ipset_access_list_conf      (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char     *ngx_ipset_priority_conf          (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void     *ngx_ipset_access_create_loc_conf (ngx_conf_t *cf);
static char     *ngx_ipset_access_merge_loc_conf  (ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_ipset_access_init            (ngx_conf_t *cf);
static ngx_int_t ngx_ipset_on_init_process        (ngx_cycle_t *cycle);
static void      ngx_ipset_on_exit_process         (ngx_cycle_t *cycle);
static ngx_int_t ngx_ipset_access_handler         (ngx_http_request_t *r);
static ngx_int_t ngx_ipset_check_blacklist        (ngx_http_request_t *r, ngx_ipset_access_loc_conf_t *conf, int af);
static ngx_int_t ngx_ipset_check_whitelist        (ngx_http_request_t *r, ngx_ipset_access_loc_conf_t *conf, int af);
 
 
// -----------------------------------------------------------------------
// Nginx module ABI
 
static ngx_command_t ngx_ipset_access_commands[] = {
 
    {   ngx_string("blacklist"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1 | NGX_CONF_TAKE2,
        ngx_ipset_access_list_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
 
    {   ngx_string("whitelist"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1 | NGX_CONF_TAKE2,
        ngx_ipset_access_list_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
 
    {   ngx_string("ipset_priority"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
        ngx_ipset_priority_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
 
    ngx_null_command
};
 
 
static ngx_http_module_t ngx_ipset_blocklist_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_ipset_access_init,              /* postconfiguration */
 
    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */
 
    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
 
    ngx_ipset_access_create_loc_conf,   /* create location configuration */
    ngx_ipset_access_merge_loc_conf,    /* merge location configuration */
};
 
 
ngx_module_t ngx_ipset_blocklist = {
    NGX_MODULE_V1,
    &ngx_ipset_blocklist_module_ctx,    /* module context */
    ngx_ipset_access_commands,          /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    ngx_ipset_on_init_process,          /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    ngx_ipset_on_exit_process,          /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};
 
 
// -----------------------------------------------------------------------
// Configuration lifecycle
 
static void *ngx_ipset_access_create_loc_conf(ngx_conf_t *cf)
{
    ngx_ipset_access_loc_conf_t *conf;
 
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_ipset_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
 
    // ngx_pcalloc zeroes memory:
    //   blacklist/whitelist == IPSET_LIST_UNSET (0)
    //   priority            == IPSET_PRIORITY_UNSET (0)
    return conf;
}
 
 
static char *ngx_ipset_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ipset_access_loc_conf_t *prev = parent;
    ngx_ipset_access_loc_conf_t *conf = child;

    // Merge blacklist from parent
    if (conf->blacklist == IPSET_LIST_UNSET) {
        conf->blacklist = prev->blacklist;
    }

    if (prev->blacklist == IPSET_LIST_ON && conf->blacklist != IPSET_LIST_OFF) {
        for (ngx_uint_t i = 0; i < prev->blacklist_set4_count; i++) {
            if (conf->blacklist_set4_count < NGX_IPSET_MAX_SETS) {
                ngx_memcpy(conf->blacklist_set4[conf->blacklist_set4_count],
                           prev->blacklist_set4[i],
                           IP_SET_MAXNAMELEN);
                conf->blacklist_set4_count++;
            }
        }

        for (ngx_uint_t i = 0; i < prev->blacklist_set6_count; i++) {
            if (conf->blacklist_set6_count < NGX_IPSET_MAX_SETS) {
                ngx_memcpy(conf->blacklist_set6[conf->blacklist_set6_count],
                           prev->blacklist_set6[i],
                           IP_SET_MAXNAMELEN);
                conf->blacklist_set6_count++;
            }
        }
    }

    // Merge whitelist from parent
    if (conf->whitelist == IPSET_LIST_UNSET) {
        conf->whitelist = prev->whitelist;
    }

    if (prev->whitelist == IPSET_LIST_ON && conf->whitelist != IPSET_LIST_OFF) {
        for (ngx_uint_t i = 0; i < prev->whitelist_set4_count; i++) {
            if (conf->whitelist_set4_count < NGX_IPSET_MAX_SETS) {
                ngx_memcpy(conf->whitelist_set4[conf->whitelist_set4_count],
                           prev->whitelist_set4[i],
                           IP_SET_MAXNAMELEN);
                conf->whitelist_set4_count++;
            }
        }

        for (ngx_uint_t i = 0; i < prev->whitelist_set6_count; i++) {
            if (conf->whitelist_set6_count < NGX_IPSET_MAX_SETS) {
                ngx_memcpy(conf->whitelist_set6[conf->whitelist_set6_count],
                           prev->whitelist_set6[i],
                           IP_SET_MAXNAMELEN);
                conf->whitelist_set6_count++;
            }
        }
    }

    // Inherit priority from parent; fall back to default (blacklist first)
    if (conf->priority == IPSET_PRIORITY_UNSET) {
        conf->priority = (prev->priority != IPSET_PRIORITY_UNSET)
                         ? prev->priority
                         : IPSET_PRIORITY_BLACKLIST;
    }

    return NGX_CONF_OK;
}
 
// Shared handler for both "blacklist" and "whitelist" directives
static char *ngx_ipset_access_list_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *p_conf)
{
    ngx_ipset_access_loc_conf_t *conf = p_conf;
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  argc = cf->args->nelts;

    ngx_uint_t is_blacklist = (value[0].data[0] == 'b');

    ngx_uint_t *list_state;
    char (*set4)[IP_SET_MAXNAMELEN];
    char (*set6)[IP_SET_MAXNAMELEN];
    ngx_uint_t *set4_count;
    ngx_uint_t *set6_count;

    if (is_blacklist) {
        list_state  = &conf->blacklist;
        set4         = conf->blacklist_set4;
        set6         = conf->blacklist_set6;
        set4_count   = &conf->blacklist_set4_count;
        set6_count   = &conf->blacklist_set6_count;
    } else {
        list_state  = &conf->whitelist;
        set4         = conf->whitelist_set4;
        set6         = conf->whitelist_set6;
        set4_count   = &conf->whitelist_set4_count;
        set6_count   = &conf->whitelist_set6_count;
    }

    // Handle explicit "off"
    if (argc == 2 && value[1].len == 3 &&
        ngx_strcmp(value[1].data, "off") == 0) {

        *list_state = IPSET_LIST_OFF;
        *set4_count = 0;
        *set6_count = 0;

        return NGX_CONF_OK;
    }

    *list_state = IPSET_LIST_ON;

        // One argument: same ipset is used for IPv4 and IPv6.
    // Two arguments: first ipset is IPv4, second ipset is IPv6.
    // Multiple directives in the same context are additive.

    if (argc == 2) {

        if (*set4_count >= NGX_IPSET_MAX_SETS ||
            *set6_count >= NGX_IPSET_MAX_SETS) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ipset_blocklist: too many ipset entries (max %d)",
                NGX_IPSET_MAX_SETS);
            return NGX_CONF_ERROR;
        }

        if (value[1].len == 0 ||
            value[1].len >= IP_SET_MAXNAMELEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ipset_blocklist: invalid set name \"%V\"",
                &value[1]);
            return NGX_CONF_ERROR;
        }

        ngx_memzero(set4[*set4_count], IP_SET_MAXNAMELEN);
        ngx_memcpy(set4[*set4_count], value[1].data, value[1].len);
        (*set4_count)++;

        ngx_memzero(set6[*set6_count], IP_SET_MAXNAMELEN);
        ngx_memcpy(set6[*set6_count], value[1].data, value[1].len);
        (*set6_count)++;

    } else if (argc == 3) {

        if (*set4_count >= NGX_IPSET_MAX_SETS ||
            *set6_count >= NGX_IPSET_MAX_SETS) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ipset_blocklist: too many ipset entries (max %d)",
                NGX_IPSET_MAX_SETS);
            return NGX_CONF_ERROR;
        }

        if (value[1].len == 0 ||
            value[1].len >= IP_SET_MAXNAMELEN ||
            value[2].len == 0 ||
            value[2].len >= IP_SET_MAXNAMELEN) {

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ipset_blocklist: invalid ipset name in \"%V\" directive",
                &value[0]);
            return NGX_CONF_ERROR;
        }

        // IPv4 set
        ngx_memzero(set4[*set4_count], IP_SET_MAXNAMELEN);
        ngx_memcpy(set4[*set4_count], value[1].data, value[1].len);
        (*set4_count)++;

        // IPv6 set
        ngx_memzero(set6[*set6_count], IP_SET_MAXNAMELEN);
        ngx_memcpy(set6[*set6_count], value[2].data, value[2].len);
        (*set6_count)++;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "ipset_blocklist: invalid number of arguments in \"%V\" directive",
            &value[0]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
 
 
// Handler for "ipset_priority blacklist|whitelist"
static char *ngx_ipset_priority_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *p_conf)
{
    ngx_ipset_access_loc_conf_t *conf = p_conf;
    ngx_str_t *value = cf->args->elts;
    // value[0] = "ipset_priority", value[1] = "blacklist" or "whitelist"
 
    if (ngx_strcmp(value[1].data, "blacklist") == 0) {
        conf->priority = IPSET_PRIORITY_BLACKLIST;
    } else if (ngx_strcmp(value[1].data, "whitelist") == 0) {
        conf->priority = IPSET_PRIORITY_WHITELIST;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "ipset_blocklist: invalid ipset_priority value \"%V\""
            " — expected \"blacklist\" or \"whitelist\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }
 
    return NGX_CONF_OK;
}
 
 
// -----------------------------------------------------------------------
// Process lifecycle
 
static ngx_int_t ngx_ipset_on_init_process(ngx_cycle_t *cycle)
{
    if (init_ipset_test_clnt() != EXIT_SUCCESS) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
            "ipset_blocklist: failed to connect to ipset RPC server on localhost");
        return NGX_ERROR;
    }
 
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "ipset_blocklist: connected to ipset RPC server");
 
    return NGX_OK;
}
 
 
static void ngx_ipset_on_exit_process(ngx_cycle_t *cycle)
{
    deinit_ipset_test_clnt();
}
 
 
// -----------------------------------------------------------------------
// Per-list check helpers (return NGX_HTTP_CLOSE_REQUEST or NGX_DECLINED)

static ngx_int_t
ngx_ipset_check_blacklist(ngx_http_request_t *r,
    ngx_ipset_access_loc_conf_t *conf, int af)
{
    char (*sets)[IP_SET_MAXNAMELEN];
    ngx_uint_t count;
    int res;

    if (conf->blacklist != IPSET_LIST_ON) {
        return NGX_DECLINED;
    }

    if (af == AF_INET) {
        sets  = conf->blacklist_set4;
        count = conf->blacklist_set4_count;
    } else {
        sets  = conf->blacklist_set6;
        count = conf->blacklist_set6_count;
    }

    for (ngx_uint_t i = 0; i < count; i++) {

        res = test_ipaddr_in_ipset(sets[i], af, r->connection->sockaddr);

        if (res == EXIT_FAILURE) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "ipset_blocklist: RPC error querying blacklist \"%s\""
                " for client %V — request passed through",
                sets[i], &r->connection->addr_text);
            continue;   // fail-open for this set, try remaining sets
        }

        if (res == IPADDR_IN_IPSET) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ipset_blocklist: access denied by blacklist \"%s\", client=%V",
                sets[i], &r->connection->addr_text);
            r->keepalive = 0;
            return NGX_HTTP_CLOSE_REQUEST;
        }
    }

    return NGX_DECLINED;   // IP not in any blacklist set — continue
}
 
 
static ngx_int_t
ngx_ipset_check_whitelist(ngx_http_request_t *r,
    ngx_ipset_access_loc_conf_t *conf, int af)
{
    char (*sets)[IP_SET_MAXNAMELEN];
    ngx_uint_t count;
    int res;

    if (conf->whitelist != IPSET_LIST_ON) {
        return NGX_DECLINED;
    }

    if (af == AF_INET) {
        sets  = conf->whitelist_set4;
        count = conf->whitelist_set4_count;
    } else {
        sets  = conf->whitelist_set6;
        count = conf->whitelist_set6_count;
    }

    for (ngx_uint_t i = 0; i < count; i++) {

        res = test_ipaddr_in_ipset(sets[i], af, r->connection->sockaddr);

        if (res == EXIT_FAILURE) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "ipset_blocklist: RPC error querying whitelist \"%s\""
                " for client %V — request passed through",
                sets[i], &r->connection->addr_text);
            continue;
        }

        if (res == IPADDR_IN_IPSET) {
            return NGX_DECLINED;   // IP found in at least one whitelist
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "ipset_blocklist: access denied by whitelist (IP %V not in any set)",
        &r->connection->addr_text);

    r->keepalive = 0;
    return NGX_HTTP_CLOSE_REQUEST;
}
 
 
// -----------------------------------------------------------------------
// Request handler

static ngx_int_t ngx_ipset_access_handler(ngx_http_request_t *r)
{
    ngx_ipset_access_loc_conf_t *conf;
    ngx_int_t  rc;
    int        af;

    conf = ngx_http_get_module_loc_conf(r, ngx_ipset_blocklist);

    // Nothing active — skip entirely
    if (conf->blacklist != IPSET_LIST_ON && conf->whitelist != IPSET_LIST_ON) {
        return NGX_DECLINED;
    }

    af = (int) r->connection->sockaddr->sa_family;

    if (conf->priority == IPSET_PRIORITY_WHITELIST) {

        // Whitelist first: a whitelisted IP is allowed regardless of blacklist.
        // If IP is found in any whitelist set, request passes.
        // If IP is not in any whitelist set, deny immediately.

        if (conf->whitelist == IPSET_LIST_ON) {

            ngx_uint_t i;
            ngx_uint_t count = (af == AF_INET)
                ? conf->whitelist_set4_count
                : conf->whitelist_set6_count;

            char (*sets)[IP_SET_MAXNAMELEN] = (af == AF_INET)
                ? conf->whitelist_set4
                : conf->whitelist_set6;

            for (i = 0; i < count; i++) {

                int res = test_ipaddr_in_ipset(
                    sets[i],
                    af,
                    r->connection->sockaddr
                );

                if (res == EXIT_FAILURE) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "ipset_blocklist: RPC error querying whitelist \"%s\""
                        " for client %V — request passed through",
                        sets[i], &r->connection->addr_text);

                    return NGX_OK;   // fail-open
                }

                if (res == IPADDR_IN_IPSET) {
                    // IP is in one whitelist set — allow immediately
                    return NGX_OK;
                }
            }

            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ipset_blocklist: access denied by whitelist (client %V not found in any set)",
                &r->connection->addr_text);

            r->keepalive = 0;
            return NGX_HTTP_CLOSE_REQUEST;
        }

        // Whitelist not configured, but priority=whitelist was set:
        // fall through to blacklist check only
        rc = ngx_ipset_check_blacklist(r, conf, af);
        return (rc == NGX_DECLINED) ? NGX_OK : rc;

    } else {

        // Default: blacklist first.
        // Any blacklist match denies the request.

        rc = ngx_ipset_check_blacklist(r, conf, af);

        if (rc != NGX_DECLINED) {
            return rc;
        }

        rc = ngx_ipset_check_whitelist(r, conf, af);

        return (rc == NGX_DECLINED) ? NGX_OK : rc;
    }
}
 
 
// -----------------------------------------------------------------------
// postconfiguration: register our handler in the ACCESS phase
 
static ngx_int_t ngx_ipset_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;
 
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
 
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_ipset_access_handler;
 
    return NGX_OK;
}
