//
// Nginx HTTP ipset blacklist/whitelist access module
// Created by kraloveckey
// Features: location-level directives, simultaneous blacklist+whitelist,
//          single-name syntax, proper merge logic, improved logging/errors,
//          configurable check order via ipset_priority
//
// Directives (usable in http{}, server{}, location{}):
//
//   blacklist "setname";                  # same ipset for IPv4 and IPv6
//   blacklist "setname4" "setname6";      # separate ipsets per AF
//   blacklist off;                        # disable at this level
//
//   whitelist "setname";
//   whitelist "setname4" "setname6";
//   whitelist off;
//
//   ipset_priority blacklist;             # check blacklist first (default)
//   ipset_priority whitelist;             # check whitelist first
//
// Logic:
//   - blacklist: deny (403) if IP is IN the set
//   - whitelist: deny (403) if IP is NOT IN the set
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
 
typedef struct {
    ngx_uint_t  blacklist;                         // IPSET_LIST_UNSET / OFF / ON
    char        blacklist_set4[IP_SET_MAXNAMELEN];  // ipset name for AF_INET
    char        blacklist_set6[IP_SET_MAXNAMELEN];  // ipset name for AF_INET6
 
    ngx_uint_t  whitelist;
    char        whitelist_set4[IP_SET_MAXNAMELEN];
    char        whitelist_set6[IP_SET_MAXNAMELEN];
 
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
 
    // Inherit blacklist from parent only if not configured at this level
    if (conf->blacklist == IPSET_LIST_UNSET) {
        conf->blacklist = prev->blacklist;
        ngx_memcpy(conf->blacklist_set4, prev->blacklist_set4, IP_SET_MAXNAMELEN);
        ngx_memcpy(conf->blacklist_set6, prev->blacklist_set6, IP_SET_MAXNAMELEN);
    }
 
    // Inherit whitelist from parent only if not configured at this level
    if (conf->whitelist == IPSET_LIST_UNSET) {
        conf->whitelist = prev->whitelist;
        ngx_memcpy(conf->whitelist_set4, prev->whitelist_set4, IP_SET_MAXNAMELEN);
        ngx_memcpy(conf->whitelist_set6, prev->whitelist_set6, IP_SET_MAXNAMELEN);
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
    ngx_uint_t  argc  = cf->args->nelts;
 
    // Which directive triggered us?
    ngx_uint_t  is_blacklist = (value[0].data[0] == 'b');
 
    ngx_uint_t *list_state;
    char       *set4;
    char       *set6;
 
    if (is_blacklist) {
        list_state = &conf->blacklist;
        set4       =  conf->blacklist_set4;
        set6       =  conf->blacklist_set6;
    } else {
        list_state = &conf->whitelist;
        set4       =  conf->whitelist_set4;
        set6       =  conf->whitelist_set6;
    }
 
    // Handle explicit "off"
    if (argc == 2 && value[1].len == 3 && ngx_strcmp(value[1].data, "off") == 0) {
        *list_state = IPSET_LIST_OFF;
        ngx_memzero(set4, IP_SET_MAXNAMELEN);
        ngx_memzero(set6, IP_SET_MAXNAMELEN);
        return NGX_CONF_OK;
    }
 
    // Validate set name length(s)
    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "ipset_blocklist: empty set name in \"%V\" directive", &value[0]);
        return NGX_CONF_ERROR;
    }
    if (value[1].len >= IP_SET_MAXNAMELEN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "ipset_blocklist: set name \"%V\" is too long (max %d characters)",
            &value[1], IP_SET_MAXNAMELEN - 1);
        return NGX_CONF_ERROR;
    }
 
    ngx_memzero(set4, IP_SET_MAXNAMELEN);
    ngx_memzero(set6, IP_SET_MAXNAMELEN);
 
    ngx_memcpy(set4, value[1].data, value[1].len);
 
    if (argc == 3) {
        // Two set names: separate IPv4 / IPv6 sets
        if (value[2].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ipset_blocklist: empty IPv6 set name in \"%V\" directive", &value[0]);
            return NGX_CONF_ERROR;
        }
        if (value[2].len >= IP_SET_MAXNAMELEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ipset_blocklist: set name \"%V\" is too long (max %d characters)",
                &value[2], IP_SET_MAXNAMELEN - 1);
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(set6, value[2].data, value[2].len);
    } else {
        // One name: use the same set for both address families
        ngx_memcpy(set6, value[1].data, value[1].len);
    }
 
    *list_state = IPSET_LIST_ON;
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
// Per-list check helpers (return NGX_HTTP_FORBIDDEN or NGX_DECLINED)
 
static ngx_int_t
ngx_ipset_check_blacklist(ngx_http_request_t *r,
    ngx_ipset_access_loc_conf_t *conf, int af)
{
    char *setname;
    int   res;
 
    if (conf->blacklist != IPSET_LIST_ON) {
        return NGX_DECLINED;
    }
 
    setname = (af == AF_INET) ? conf->blacklist_set4 : conf->blacklist_set6;
    res     = test_ipaddr_in_ipset(setname, af, r->connection->sockaddr);
 
    if (res == EXIT_FAILURE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "ipset_blocklist: RPC error querying blacklist \"%s\""
            " — request passed through", setname);
        return NGX_DECLINED;   // fail-open
    }
 
    if (res == IPADDR_IN_IPSET) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ipset_blocklist: access denied by blacklist \"%s\"", setname);
        r->keepalive = 0;
        return NGX_HTTP_FORBIDDEN;
    }
 
    return NGX_DECLINED;   // IP not in blacklist — continue
}
 
 
static ngx_int_t
ngx_ipset_check_whitelist(ngx_http_request_t *r,
    ngx_ipset_access_loc_conf_t *conf, int af)
{
    char *setname;
    int   res;
 
    if (conf->whitelist != IPSET_LIST_ON) {
        return NGX_DECLINED;
    }
 
    setname = (af == AF_INET) ? conf->whitelist_set4 : conf->whitelist_set6;
    res     = test_ipaddr_in_ipset(setname, af, r->connection->sockaddr);
 
    if (res == EXIT_FAILURE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "ipset_blocklist: RPC error querying whitelist \"%s\""
            " — request passed through", setname);
        return NGX_DECLINED;   // fail-open
    }
 
    if (res == IPADDR_NOT_IN_IPSET) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ipset_blocklist: access denied by whitelist \"%s\" (IP not in set)",
            setname);
        r->keepalive = 0;
        return NGX_HTTP_FORBIDDEN;
    }
 
    return NGX_DECLINED;   // IP is in whitelist — continue
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
        // Only if the whitelist passes (IP is in set) do we skip blacklist.
        // If whitelist denies → 403 immediately.
        // If whitelist is not configured → fall through to blacklist.
        if (conf->whitelist == IPSET_LIST_ON) {
            char *setname = (af == AF_INET)
                            ? conf->whitelist_set4 : conf->whitelist_set6;
            int res = test_ipaddr_in_ipset(setname, af, r->connection->sockaddr);
 
            if (res == EXIT_FAILURE) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "ipset_blocklist: RPC error querying whitelist \"%s\""
                    " — request passed through", setname);
                return NGX_OK;   // fail-open: skip remaining checks too
            }
 
            if (res == IPADDR_IN_IPSET) {
                // IP is whitelisted — passes unconditionally, skip blacklist
                return NGX_OK;
            }
 
            // IP is NOT in whitelist — deny immediately, skip blacklist
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ipset_blocklist: access denied by whitelist \"%s\" (IP not in set)",
                setname);
            r->keepalive = 0;
            return NGX_HTTP_FORBIDDEN;
        }
 
        // Whitelist not configured, but priority=whitelist was set:
        // fall through to blacklist check only
        rc = ngx_ipset_check_blacklist(r, conf, af);
        return (rc == NGX_DECLINED) ? NGX_OK : rc;
 
    } else {
        // Default: blacklist first.
        // Blacklist can deny even a whitelisted IP.
        rc = ngx_ipset_check_blacklist(r, conf, af);
        if (rc != NGX_DECLINED) {
            return rc;   // denied by blacklist
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