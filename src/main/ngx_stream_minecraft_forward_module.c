#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include "ngx_stream_minecraft_forward_module.h"
#include "../utils/nsmfm_hostname.h"

static void *nsmfm_create_srv_conf(ngx_conf_t *cf);
static char *nsmfm_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static char *nsmfm_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t nsmfm_pre_init(ngx_conf_t *cf);

#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_ 512
#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_ 64

static ngx_command_t nsmfm_directives[] = {
    {ngx_string("minecraft_server_forward"),
     NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, enabled),
     NULL},
    {ngx_string("minecraft_server_hostname"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE23,
     nsmfm_srv_conf_minecraft_server_hostname,
     NGX_STREAM_SRV_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("minecraft_server_hostname_hash_max_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, hash_max_size),
     NULL},
    {ngx_string("minecraft_server_hostname_hash_bucket_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, hash_bucket_size),
     NULL},
    {ngx_string("minecraft_server_hostname_disconnect_on_nomatch"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, disconnect_on_nomatch),
     NULL},
    {ngx_string("minecraft_server_hostname_replace_on_ping"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(nsmfm_srv_conf_t, replace_on_ping),
     NULL},
    ngx_null_command,
};

static ngx_stream_module_t nsmfm_conf_ctx = {
    nsmfm_pre_init,  /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    nsmfm_create_srv_conf, /* create server configuration */
    nsmfm_merge_srv_conf   /* merge server configuration */
};

ngx_module_t ngx_stream_minecraft_forward_module = {
    NGX_MODULE_V1,
    &nsmfm_conf_ctx,       /* module conf context */
    nsmfm_directives,      /* module directives */
    NGX_STREAM_MODULE,     /* module type */
    NULL,                  /* init master */
    NULL,                  /* init module */
    NULL,                  /* init process */
    NULL,                  /* init thread */
    NULL,                  /* exit thread */
    NULL,                  /* exit process */
    NULL,                  /* exit master */
    NGX_MODULE_V1_PADDING  /* No padding */
};

static void *nsmfm_create_srv_conf(ngx_conf_t *cf) {
    ngx_int_t         rc;
    nsmfm_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(nsmfm_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->disconnect_on_nomatch = NGX_CONF_UNSET;

    conf->hostname_map_init.hash = &conf->hostname_map;
    conf->hostname_map_init.key = ngx_hash_key_lc;
    conf->hostname_map_init.name = "minecraft_server_hostname";
    conf->hostname_map_init.pool = cf->pool;
    conf->hostname_map_init.temp_pool = cf->temp_pool;
    conf->hash_max_size = NGX_CONF_UNSET_SIZE;
    conf->hash_bucket_size = NGX_CONF_UNSET_SIZE;
    conf->hostname_map_keys.pool = cf->pool;
    conf->hostname_map_keys.temp_pool = cf->temp_pool;

    rc = ngx_hash_keys_array_init(&conf->hostname_map_keys, NGX_HASH_SMALL);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem adding hash key, possibly because of duplicate entry");
        ngx_pfree(cf->pool, conf);
        return NULL;
    }

    conf->replace_on_ping = NGX_CONF_UNSET;

    return conf;
}

static char *nsmfm_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_int_t   rc;
    ngx_str_t  *values;
    ngx_str_t  *key;
    ngx_str_t  *val;

    nsmfm_srv_conf_t *sc = conf;

    values = cf->args->elts;

    key = &values[1];
    val = &values[2];

    if (cf->args->nelts >= 3 + 1) {
        if (ngx_strcmp(values[3].data, "arbitrary") == 0) {
            goto conf_validation_pass;
        }
    }

    if (!nsmfm_validate_hostname(key)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid entry: %V", key);
        return NGX_CONF_ERROR;
    }
    if (!nsmfm_validate_hostname(val)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid value: %V", key);
        return NGX_CONF_ERROR;
    }

conf_validation_pass:
    rc = ngx_hash_add_key(&sc->hostname_map_keys, key, val, NGX_HASH_READONLY_KEY);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem adding hash key, possibly because of duplicate entry");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *nsmfm_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_int_t          rc;
    nsmfm_srv_conf_t  *pconf;
    nsmfm_srv_conf_t  *cconf;

    ngx_str_t         *key;
    ngx_uint_t         hashed_key;
    ngx_str_t         *val;

    pconf = prev;
    cconf = conf;

    ngx_conf_merge_value(cconf->enabled, pconf->enabled, 0);
    ngx_conf_merge_value(cconf->disconnect_on_nomatch, pconf->disconnect_on_nomatch, 0);
    ngx_conf_merge_value(cconf->replace_on_ping, pconf->replace_on_ping, 1);

    ngx_conf_merge_size_value(pconf->hash_max_size,
        NGX_CONF_UNSET_SIZE, _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_);

    ngx_conf_merge_size_value(pconf->hash_bucket_size,
        NGX_CONF_UNSET_SIZE, _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_);

    ngx_conf_merge_size_value(cconf->hash_max_size, pconf->hash_max_size,
        _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_);

    ngx_conf_merge_size_value(cconf->hash_bucket_size, pconf->hash_bucket_size,
        _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_);

    pconf->hostname_map_init.max_size = pconf->hash_max_size;
    pconf->hostname_map_init.bucket_size = ngx_align(pconf->hash_bucket_size, ngx_cacheline_size);

    rc = ngx_hash_init(&pconf->hostname_map_init,
                       pconf->hostname_map_keys.keys.elts,
                       pconf->hostname_map_keys.keys.nelts);

    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem initializing hash table in stream context");
        return NGX_CONF_ERROR;
    }

    // MERGE HASH TABLE
    for (ngx_uint_t i = 0; i < pconf->hostname_map_keys.keys.nelts; ++i) {
        key = &((ngx_hash_key_t *)pconf->hostname_map_keys.keys.elts + i)->key;

        hashed_key = ngx_hash_key(key->data, key->len);

        val = (ngx_str_t *)ngx_hash_find(&pconf->hostname_map, hashed_key, key->data, key->len);

        if (val == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "A hash key previously in stream context becomes missing?! This should not happen");
            return NGX_CONF_ERROR;
        }

        rc = ngx_hash_add_key(&cconf->hostname_map_keys, key, val, NGX_HASH_READONLY_KEY);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "There's a problem merging hash table%s",
                               rc == NGX_BUSY ? " because of duplicate entry" : "");
            return NGX_CONF_ERROR;
        }
    }

    cconf->hostname_map_init.max_size = cconf->hash_max_size;
    cconf->hostname_map_init.bucket_size = ngx_align(cconf->hash_bucket_size, ngx_cacheline_size);

    rc = ngx_hash_init(&cconf->hostname_map_init,
                       cconf->hostname_map_keys.keys.elts,
                       cconf->hostname_map_keys.keys.nelts);

    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem initializing hash table in server context");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#if (NGX_PCRE)
ngx_regex_t *nsmfm_validate_hostname_regex = NULL;
#endif

static ngx_int_t nsmfm_pre_init(ngx_conf_t *cf) {
#if (NGX_PCRE)
    ngx_regex_compile_t rc;

    u_char errstr[NGX_MAX_CONF_ERRSTR];

    ngx_str_t pattern = ngx_string("(?!^.{253,}$)(?:(^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$|(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,6}$)|(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)))");

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = pattern;
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.options = NGX_REGEX_CASELESS;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    nsmfm_validate_hostname_regex = rc.regex;
#endif
    return NGX_OK;
}
