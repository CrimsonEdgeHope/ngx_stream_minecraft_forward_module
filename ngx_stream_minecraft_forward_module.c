#include "ngx_stream_minecraft_forward_module.h"
#include "ngx_stream_minecraft_forward_module_utils.h"
#include "ngx_stream_minecraft_protocol_numbers.h"

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain, ngx_uint_t from_upstream);

static ngx_int_t ngx_stream_minecraft_forward_module_pre_init(ngx_conf_t *cf);
static ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf);

ngx_stream_filter_pt ngx_stream_next_filter;

#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_ 512
#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_ 64
#define _PACKET_ID_ 0

static ngx_command_t ngx_stream_minecraft_forward_module_directives[] = {
    {ngx_string("minecraft_server_forward"),
     NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, enabled),
     NULL},
    {ngx_string("minecraft_server_hostname"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE23,
     ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_hostname,
     NGX_STREAM_SRV_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("minecraft_server_hostname_hash_max_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, hash_max_size),
     NULL},
    {ngx_string("minecraft_server_hostname_hash_bucket_size"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, hash_bucket_size),
     NULL},
    {ngx_string("minecraft_server_hostname_disconnect_on_nomatch"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, disconnect_on_nomatch),
     NULL},
    {ngx_string("minecraft_server_hostname_replace_on_ping"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, replace_on_ping),
     NULL},
    ngx_null_command,
};

static ngx_stream_module_t ngx_stream_minecraft_forward_module_conf_ctx = {
    ngx_stream_minecraft_forward_module_pre_init,  /* preconfiguration */
    ngx_stream_minecraft_forward_module_post_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_stream_minecraft_forward_module_create_srv_conf, /* create server configuration */
    ngx_stream_minecraft_forward_module_merge_srv_conf   /* merge server configuration */
};

ngx_module_t ngx_stream_minecraft_forward_module = {
    NGX_MODULE_V1,
    &ngx_stream_minecraft_forward_module_conf_ctx,  /* module conf context */
    ngx_stream_minecraft_forward_module_directives, /* module directives */
    NGX_STREAM_MODULE,                              /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    NULL,                                           /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING                           /* No padding */
};

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf) {
    ngx_int_t                                       rc;
    ngx_stream_minecraft_forward_module_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_minecraft_forward_module_srv_conf_t));
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

static char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_int_t                                       rc;
    ngx_str_t                                      *values;
    ngx_str_t                                      *key;
    ngx_str_t                                      *val;

    ngx_stream_minecraft_forward_module_srv_conf_t *sc;

    sc = conf;

    values = cf->args->elts;

    key = &values[1];
    val = &values[2];

    if (cf->args->nelts >= 3 + 1) {
        if (ngx_strcmp(values[3].data, "arbitrary") == 0) {
            goto validation_pass;
        }
    }

    if (ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(key) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Invalid entry: %V", key);
        return NGX_CONF_ERROR;
    }
    if (ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(val) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Invalid value: %V", key);
        return NGX_CONF_ERROR;
    }

validation_pass:
    rc = ngx_hash_add_key(&sc->hostname_map_keys, key, val, NGX_HASH_READONLY_KEY);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "There's a problem adding hash key, possibly because of duplicate entry");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_int_t                                       rc;
    ngx_stream_minecraft_forward_module_srv_conf_t *pconf;
    ngx_stream_minecraft_forward_module_srv_conf_t *cconf;

    ngx_str_t                                      *key;
    ngx_uint_t                                      hashed_key;
    ngx_str_t                                      *val;

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

    ngx_conf_merge_size_value(cconf->hash_bucket_size, pconf->hash_bucket_size,     _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_);

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

void remove_module_ctx(ngx_stream_session_t *s) {
    ngx_stream_minecraft_forward_ctx_t *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    if (ctx) {
        if (ctx->pool) {
            ngx_destroy_pool(ctx->pool);
            ctx->pool = NULL;
        }
        ngx_pfree(s->connection->pool, ctx);
    }

    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_module);
}

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s) {
    ngx_connection_t                                *c;
    ngx_stream_minecraft_forward_module_srv_conf_t  *sconf;
    ngx_stream_minecraft_forward_ctx_t              *ctx;

    ngx_int_t                                        rc;

    c = s->connection;

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);
    if (!sconf->enabled) {
        return NGX_DECLINED;
    }

    c->log->action = "prereading minecraft packet";

    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {

        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_minecraft_forward_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctx->preread_handler = ngx_stream_minecraft_forward_module_handshake_preread;

        ctx->pool = ngx_create_pool(2048, c->log);
        if (ctx->pool == NULL) {
            goto preread_failure;
        }

        ctx->out = NULL;

        ngx_stream_set_ctx(s, ctx, ngx_stream_minecraft_forward_module);
    }

    if (ctx->preread_pass) {
        return NGX_OK;
    }

    rc = ctx->preread_handler(s);

    if (rc == NGX_ERROR) {
        goto preread_failure;
    }

end_of_preread:
    if (ctx->fail) {
        remove_module_ctx(s);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Preread failed");
        return NGX_ERROR;
    }

    return rc;

preread_failure:
    ctx->fail = 1;
    goto end_of_preread;
}

static ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s) {
    ngx_connection_t                                 *c;
    ngx_stream_minecraft_forward_ctx_t               *ctx;

    u_char                                           *bufpos;
    ngx_int_t                                         vp;

    c = s->connection;

    c->log->action = "prereading minecraft handshake packet";

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    bufpos = c->buffer->pos;

    if (!ctx->handshake) {
        ctx->handshake = ngx_pcalloc(ctx->pool, sizeof(ngx_stream_minecraft_packet_t));
        if (!ctx->handshake) {
            return NGX_ERROR;
        }
    }

    if (!ctx->handshake->content.data) {
        bufpos = parse_packet_length(s, bufpos, &ctx->handshake->content.len, &ctx->handshake->varint_of_length.varint.len);

        if (!bufpos) {
            if (c->buffer->last - c->buffer->pos < _MC_VARINT_MAX_BYTE_LEN_) {
                return NGX_AGAIN;
            }
            return NGX_ERROR;
        }

        if (c->buffer->last - bufpos < (ssize_t)ctx->handshake->content.len) {
            return NGX_AGAIN;
        }

#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "read varint, handshake content len: %d", ctx->handshake->content.len);
#endif

        ctx->handshake->varint_of_length.varint.data =
            ngx_pcalloc(ctx->pool, ctx->handshake->varint_of_length.varint.len);

        if (!ctx->handshake->varint_of_length.varint.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->handshake->varint_of_length.varint.data,
            bufpos - ctx->handshake->varint_of_length.varint.len,
            ctx->handshake->varint_of_length.varint.len
        );

        ctx->handshake->content.data = ngx_pcalloc(ctx->pool, ctx->handshake->content.len);
        if (!ctx->handshake->content.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->handshake->content.data,
            bufpos,
            ctx->handshake->content.len
        );
    }

    bufpos = ctx->handshake->content.data;

    if (bufpos[0] != _PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Read unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        return NGX_ERROR;
    }

    ++bufpos;

    if (!ctx->protocol.original.varint.data) {
        vp = read_minecraft_varint(bufpos, &ctx->protocol.original.varint.len);
        if (vp == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Cannot read protocol number");
            return NGX_ERROR;
        }

        ctx->protocol.number = vp;

#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "read varint, protocol number: %d", ctx->protocol.number);
#endif

        if (is_protocol_num_acceptable(ctx->protocol) != NGX_OK) {
#if (NGX_DEBUG)
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Unacceptable protocol number: %d", ctx->protocol.number);
#endif
            return NGX_ERROR;
        }

        ctx->protocol.original.varint.data =
            ngx_pcalloc(ctx->pool, ctx->protocol.original.varint.len);

        if (!ctx->protocol.original.varint.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->protocol.original.varint.data,
            bufpos,
            ctx->protocol.original.varint.len
        );
    }

    bufpos += ctx->protocol.original.varint.len;

    if (!ctx->provided_hostname.text.data) {
        vp = read_minecraft_varint(bufpos, &ctx->provided_hostname.varint_of_length.varint.len);
        if (vp == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Cannot read hostname string length");
            return NGX_ERROR;
        }

        ctx->provided_hostname.varint_of_length.varint.data =
            ngx_pcalloc(ctx->pool, ctx->provided_hostname.varint_of_length.varint.len);

        if (!ctx->provided_hostname.varint_of_length.varint.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->provided_hostname.varint_of_length.varint.data,
            bufpos,
            ctx->provided_hostname.varint_of_length.varint.len
        );

        bufpos += ctx->provided_hostname.varint_of_length.varint.len;

        ctx->provided_hostname.text.len = vp;
        ctx->provided_hostname.text.data =
            ngx_pcalloc(ctx->pool, ctx->provided_hostname.text.len);

        if (!ctx->provided_hostname.text.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->provided_hostname.text.data,
            bufpos,
            ctx->provided_hostname.text.len
        );
#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "read hostname: %V", &ctx->provided_hostname.text);
#endif
    } else {
        bufpos += ctx->provided_hostname.varint_of_length.varint.len;
    }

    bufpos += ctx->provided_hostname.text.len;

    ctx->remote_port |= (bufpos[0] << 8);
    ctx->remote_port |= bufpos[1];

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "read remote port: %d", ctx->remote_port);
#endif

    bufpos += _MC_PORT_LEN_;

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "read next state: %d", *bufpos);
#endif

    switch (*bufpos) {
        case _MC_HANDSHAKE_STATUS_STATE_:
            ctx->preread_handler = NULL;
            ctx->state = _MC_HANDSHAKE_STATUS_STATE_;
            ctx->preread_pass = 1;

            ctx->in = ngx_alloc_chain_link(ctx->pool);
            if (!ctx->in) {
                return NGX_ERROR;
            }

            if (c->buffer->last - c->buffer->start
                > (ssize_t)(ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len)) {

                ctx->in->buf =
                    ngx_create_temp_buf(ctx->pool, c->buffer->last - c->buffer->start);
                if (!ctx->in->buf) {
                    return NGX_ERROR;
                }

                ctx->in->buf->last = ngx_cpymem(
                    ctx->in->buf->pos,
                    ctx->handshake->varint_of_length.varint.data,
                    ctx->handshake->varint_of_length.varint.len
                );
                ctx->in->buf->last = ngx_cpymem(
                    ctx->in->buf->last,
                    ctx->handshake->content.data,
                    ctx->handshake->content.len
                );
                ctx->in->buf->last = ngx_cpymem(
                    ctx->in->buf->last,
                    c->buffer->start
                        + ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len,
                    (c->buffer->last - c->buffer->start)
                        - (ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len)
                );

            } else {
                ctx->in->buf =
                    ngx_create_temp_buf(ctx->pool,
                        ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len);
                if (!ctx->in->buf) {
                    return NGX_ERROR;
                }

                ctx->in->buf->last = ngx_cpymem(
                    ctx->in->buf->pos,
                    ctx->handshake->varint_of_length.varint.data,
                    ctx->handshake->varint_of_length.varint.len
                );
                ctx->in->buf->last = ngx_cpymem(
                    ctx->in->buf->last,
                    ctx->handshake->content.data,
                    ctx->handshake->content.len
                );
            }

            ctx->in->buf->last_buf = 1;
            ctx->in->next = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "Preread: Protocol number: %d, "
                          "Hostname provided: %V, "
                          "Next state: %d",
                          ctx->protocol.number,
                          &ctx->provided_hostname.text,
                          ctx->state);

            return NGX_OK;

        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            ctx->preread_handler = ngx_stream_minecraft_forward_module_loginstart_preread;
            ctx->state = _MC_HANDSHAKE_LOGINSTART_STATE_;

            break;

        default:
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unknown next state (%d)", *bufpos);
            return NGX_ERROR;
    }

    return NGX_AGAIN;
}

static ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s) {
    ngx_connection_t                     *c;
    ngx_stream_minecraft_forward_ctx_t   *ctx;

    u_char                               *bufpos;
    u_char                               *h_pos;

    u_char                               *uuid;

    ngx_int_t                             vp;

    c = s->connection;

    c->log->action = "prereading minecraft loginstart packet";

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    if (!ctx->loginstart) {
        ctx->loginstart = ngx_pcalloc(ctx->pool, sizeof(ngx_stream_minecraft_packet_t));
        if (!ctx->loginstart) {
            return NGX_ERROR;
        }
    }

    h_pos = c->buffer->pos + ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len;

    bufpos = h_pos;

    if (!ctx->loginstart->content.data) {
        bufpos = parse_packet_length(s, bufpos, &ctx->loginstart->content.len, &ctx->loginstart->varint_of_length.varint.len);

        if (!bufpos) {
            if (c->buffer->last - h_pos < _MC_VARINT_MAX_BYTE_LEN_) {
                return NGX_AGAIN;
            }
            return NGX_ERROR;
        }

        if (c->buffer->last - bufpos < (ssize_t)ctx->loginstart->content.len) {
            return NGX_AGAIN;
        }

#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "read varint, loginstart content len: %d", ctx->loginstart->content.len);
#endif

        ctx->loginstart->varint_of_length.varint.data =
            ngx_pcalloc(ctx->pool, ctx->loginstart->varint_of_length.varint.len);

        if (!ctx->loginstart->varint_of_length.varint.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->loginstart->varint_of_length.varint.data,
            bufpos - ctx->loginstart->varint_of_length.varint.len,
            ctx->loginstart->varint_of_length.varint.len
        );

        ctx->loginstart->content.data =
            ngx_pcalloc(ctx->pool, ctx->loginstart->content.len);

        if (!ctx->loginstart->content.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->loginstart->content.data,
            bufpos,
            ctx->loginstart->content.len
        );
    }

    bufpos = ctx->loginstart->content.data;

    if (bufpos[0] != _PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        return NGX_ERROR;
    }

    ++bufpos;

    if (!ctx->username.text.data) {
        vp = read_minecraft_varint(bufpos, &ctx->username.varint_of_length.varint.len);
        if (vp == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Cannot read username string length");
            return NGX_ERROR;
        }

        ctx->username.varint_of_length.varint.data =
            ngx_pcalloc(ctx->pool, ctx->username.varint_of_length.varint.len);

        if (!ctx->username.varint_of_length.varint.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->username.varint_of_length.varint.data,
            bufpos,
            ctx->username.varint_of_length.varint.len
        );

        bufpos += ctx->username.varint_of_length.varint.len;

        ctx->username.text.len = vp;
#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "read varint, username len: %d", ctx->username.text.len);
#endif

        if (ctx->username.text.len <= 0 || ctx->username.text.len > 16) {
#if (NGX_DEBUG)
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Bad username len: %d", ctx->username.text.len);
#endif
            return NGX_ERROR;
        }
        ctx->username.text.data = ngx_pcalloc(ctx->pool, ctx->username.text.len);

        if (!ctx->username.text.data) {
            return NGX_ERROR;
        }

        ngx_memcpy(
            ctx->username.text.data,
            bufpos,
            ctx->username.text.len
        );
#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "read username: %V", &ctx->username.text);
#endif
    } else {
        bufpos += ctx->username.varint_of_length.varint.len;
    }

    bufpos += ctx->username.text.len;

    if (ctx->protocol.number >= MINECRAFT_1_19_3) {
        if (ctx->protocol.number <= MINECRAFT_1_20_1) {
            ++bufpos;
        }

        uuid = ngx_pcalloc(ctx->pool, _MC_UUID_LITERAL_LEN_);

        if (uuid) {

            for (int i = 0; i < _MC_UUID_LITERAL_LEN_; ++i) {

                uuid[i] = i % 2 ? (bufpos[i / 2] & (u_char)0x0F) : ((bufpos[i / 2] & (u_char)0xF0) >> 4);

                if (uuid[i] <= 9) {
                    uuid[i] += '0';
                } else if (uuid[i] >= 10 && uuid[i] <= 15) {
                    uuid[i] = 'a' + (uuid[i] - 10);
                } else {
                    return NGX_ERROR;
                }
            }

            ctx->uuid.data = uuid;
            ctx->uuid.len = _MC_UUID_LITERAL_LEN_;

            ctx->uuid_byte.varint_of_length.varint.data =
                create_minecraft_varint(
                    ctx->pool,
                    _MC_UUID_BYTE_LEN_,
                    &ctx->uuid_byte.varint_of_length.varint.len
                );

            if (!ctx->uuid_byte.varint_of_length.varint.data) {
                return NGX_ERROR;
            }

            ctx->uuid_byte.text.data = ngx_pcalloc(ctx->pool, _MC_UUID_BYTE_LEN_);
            if (!ctx->uuid_byte.text.data) {
                return NGX_ERROR;
            }

            ctx->uuid_byte.text.len = _MC_UUID_BYTE_LEN_;
            ngx_memcpy(
                ctx->uuid_byte.text.data,
                bufpos,
                ctx->uuid_byte.text.len
            );
#if (NGX_DEBUG)
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "read uuid: %V", &ctx->uuid);
#endif
        }

        bufpos += _MC_UUID_BYTE_LEN_;
    }

    ctx->in = ngx_alloc_chain_link(ctx->pool);
    if (!ctx->in) {
        return NGX_ERROR;
    }

    ctx->in->buf = ngx_create_temp_buf(ctx->pool,
        ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len +
        ctx->loginstart->varint_of_length.varint.len + ctx->loginstart->content.len);

    if (!ctx->in->buf) {
        return NGX_ERROR;
    }

    ctx->in->buf->last = ngx_cpymem(
        ctx->in->buf->pos,
        c->buffer->pos,
        ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len +
        ctx->loginstart->varint_of_length.varint.len + ctx->loginstart->content.len
    );

    ctx->in->buf->last_buf = 1;
    ctx->in->next = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Preread: Protocol number: %d, "
                  "Hostname provided: %V, "
                  "Username: %V, "
                  "UUID: %V, "
                  "Next state: %d",
                  ctx->protocol.number,
                  &ctx->provided_hostname.text,
                  &ctx->username.text,
                  &ctx->uuid,
                  ctx->state);

    ctx->preread_pass = 1;
    return NGX_OK;
}

ngx_str_t *get_new_hostname_str(ngx_stream_minecraft_forward_module_srv_conf_t *sconf, ngx_str_t old_str) {
    if (!sconf || !old_str.data) {
        return NULL;
    }

    return (ngx_str_t *)
                ngx_hash_find(&sconf->hostname_map,
                    ngx_hash_key(old_str.data, old_str.len),
                        old_str.data, old_str.len);
}

static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain, ngx_uint_t from_upstream) {
    ngx_connection_t                               *c;

    ngx_int_t                                       rc;

    ngx_stream_minecraft_forward_ctx_t             *ctx;
    ngx_stream_minecraft_forward_module_srv_conf_t *sconf;

    size_t                                          protocol_varint_byte_len;
    u_char                                         *protocol_num_varint;

    size_t                                          old_handshake_len;
    size_t                                          new_handshake_len;
    size_t                                          new_handshake_varint_byte_len;
    u_char                                         *new_handshake_varint_bytes;

    ngx_str_t                                      *new_hostname;
    u_char                                         *new_hostname_str;
    u_char                                         *new_hostname_varint_bytes;
    size_t                                          new_hostname_varint_byte_len;
    size_t                                          new_hostname_str_len;

    u_char                                          pchar;

    size_t                                          in_buf_len;
    size_t                                          gathered_buf_len;
    ngx_chain_t                                    *target_chain_node;
    size_t                                          split_remnant_len;
    ngx_chain_t                                    *new_chain;
    ngx_chain_t                                    *split_remnant_chain;

    ngx_chain_t                                    *chain_out;
    ngx_chain_t                                   **link_i;
    ngx_chain_t                                    *append_i;

    c = s->connection;

    if (c->type != SOCK_STREAM || chain == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    c->log->action = "filtering minecraft packet";
    if (ctx->pinged) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because already used for pinging");
        goto filter_failure;
    }

    sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);

    if (from_upstream) {
        rc = ngx_stream_next_filter(s, chain, from_upstream);
        if (ctx->state == _MC_HANDSHAKE_STATUS_STATE_) {
            if (rc == NGX_OK) {
                ctx->pinged = 1;
            }
        }
        return rc;
    }

    if (!sconf->replace_on_ping && ctx->state != _MC_HANDSHAKE_LOGINSTART_STATE_) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    if (ctx->out) {
        goto chain_update;
    }

    protocol_varint_byte_len = 0;
    protocol_num_varint = NULL;

    new_handshake_len = 0;
    new_handshake_varint_byte_len = 0;
    new_handshake_varint_bytes = NULL;

    new_hostname = NULL;
    new_hostname_str = NULL;
    new_hostname_varint_bytes = NULL;
    new_hostname_varint_byte_len = 0;
    new_hostname_str_len = 0;

    switch (ctx->state) {
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            c->log->action = "filtering and forwarding new minecraft loginstart packet";
            break;
        case _MC_HANDSHAKE_STATUS_STATE_:
            c->log->action = "filtering and forwarding minecraft ping packet";
            break;
        default:
            c->log->action = "filtering minecraft packet";
            goto filter_failure;
    }

    protocol_num_varint = ctx->protocol.original.varint.data;
    protocol_varint_byte_len = ctx->protocol.original.varint.len;

    new_hostname = get_new_hostname_str(sconf, ctx->provided_hostname.text);
    if (new_hostname == NULL) {
        if (sconf->disconnect_on_nomatch) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "Closing connection because of no hostname match");
            goto filter_failure;
        }
        new_hostname_str = ctx->provided_hostname.text.data;
        new_hostname_str_len = ctx->provided_hostname.text.len;
    } else {
        new_hostname_str = new_hostname->data;
        new_hostname_str_len = new_hostname->len;
    }
    if (new_hostname_str_len <= 0) {
        goto filter_failure;
    }

    new_hostname_varint_bytes = create_minecraft_varint(ctx->pool, new_hostname_str_len, &new_hostname_varint_byte_len);
    if (new_hostname_varint_bytes == NULL) {
        goto filter_failure;
    }

    // https://wiki.vg/Protocol#Handshake
    // Packet id, Protocol Version varint, Prefixed string (Length varint + content), Server port, Next state.
    new_handshake_len = 1 + protocol_varint_byte_len + new_hostname_varint_byte_len + new_hostname_str_len + _MC_PORT_LEN_ + 1;

    // The whole packet is prefixed by a total length in varint.
    new_handshake_varint_bytes = create_minecraft_varint(ctx->pool, new_handshake_len, &new_handshake_varint_byte_len);
    if (new_handshake_varint_bytes == NULL) {
        goto filter_failure;
    }

    old_handshake_len = ctx->handshake->varint_of_length.varint.len + ctx->handshake->content.len;
#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "old_handshake_len (including varint): %d, "
                  "new_handshake_len (content): %d",
                  old_handshake_len,
                  new_handshake_len);
#endif

    new_handshake_len = new_handshake_varint_byte_len + new_handshake_len;

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "new_handshake_len (including varint): %d",
                  new_handshake_len);
#endif

    target_chain_node = NULL;

    in_buf_len = 0;
    gathered_buf_len = 0;

    for (ngx_chain_t *ln = ctx->in; ln != NULL; ln = ln->next) {

        in_buf_len = ngx_buf_size(ln->buf);

        if (in_buf_len <= 0) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "negative size of or empty buffer encountered");
            goto filter_failure;
        }

        gathered_buf_len += in_buf_len;
        if (ln->buf->last_buf) {
            if (gathered_buf_len < old_handshake_len) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Incomplete chain of buffer");
                goto filter_failure;
            }
        }

#if (NGX_DEBUG)
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "gathered_buf_len: %d", gathered_buf_len);
#endif

        if (gathered_buf_len >= old_handshake_len) {
            target_chain_node = ln;
            break;
        }
    }

    split_remnant_len = gathered_buf_len - old_handshake_len;
    split_remnant_chain = NULL;

    new_chain = ngx_chain_get_free_buf(c->pool, &ctx->free_chain);
    if (new_chain == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain to store new handshake");
        goto filter_failure;
    }

    new_chain->buf->pos = ngx_pcalloc(c->pool, new_handshake_len);
    if (new_chain->buf->pos == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain buf space");
        goto filter_failure;
    }

    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start + new_handshake_len;
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->pos, new_handshake_varint_bytes, new_handshake_varint_byte_len);

    // Packet id 0x00
    pchar = _PACKET_ID_;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, protocol_num_varint, protocol_varint_byte_len);

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_varint_bytes, new_hostname_varint_byte_len);

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_str, new_hostname_str_len);

    pchar = (ctx->remote_port & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);
    pchar = ctx->remote_port & 0x00FF;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);

    pchar = ctx->state;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);

    ngx_log_debug6(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "new_handshake_len: %d, "
                   "new_handshake_varint_byte_len: %d, "
                   "ctx protocol number: %d, "
                   "protocol_varint_byte_len: %d, "
                   "new_hostname_varint_byte_len: %d, "
                   "new_hostname_str_len: %d",
                   new_handshake_len,
                   new_handshake_varint_byte_len,
                   ctx->protocol.number,
                   protocol_varint_byte_len,
                   new_hostname_varint_byte_len,
                   new_hostname_str_len);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "split_remnant_len: %d", split_remnant_len);

    if (split_remnant_len > 0) {

        split_remnant_chain = ngx_chain_get_free_buf(c->pool, &ctx->free_chain);
        if (split_remnant_chain == NULL) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant chain");
            goto filter_failure;
        }

        split_remnant_chain->buf->pos = ngx_pcalloc(c->pool, split_remnant_len);
        if (split_remnant_chain->buf->pos == NULL) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant new buf space");
            goto filter_failure;
        }

        split_remnant_chain->buf->start = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->last = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->end = split_remnant_chain->buf->start + split_remnant_len;
        split_remnant_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
        split_remnant_chain->buf->memory = 1;

        split_remnant_chain->buf->last = ngx_cpymem(split_remnant_chain->buf->pos,
                                                    target_chain_node->buf->last - split_remnant_len,
                                                    split_remnant_len);
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Filter: Provided hostname: %V, "
                  "New hostname string: %s",
                  &ctx->provided_hostname.text,
                  new_hostname_str);


    // https://nginx.org/en/docs/dev/development_guide.html#http_body_buffers_reuse

    append_i = NULL;
    link_i = &chain_out;

    *link_i = new_chain;
    link_i = &new_chain->next;

    append_i = ngx_alloc_chain_link(c->pool);
    if (append_i == NULL) {
        goto filter_failure;
    }
    append_i->buf = NULL;
    append_i->next = NULL;

    if (split_remnant_chain != NULL) {
        if (target_chain_node->next != NULL) {
            *link_i = split_remnant_chain;
            link_i = &split_remnant_chain->next;

            append_i->buf = target_chain_node->next->buf;
            append_i->next = target_chain_node->next->next;
        } else {
            append_i->buf = split_remnant_chain->buf;
            append_i->next = split_remnant_chain->next;
        }
    } else if (target_chain_node->next != NULL) {
        append_i->buf = target_chain_node->next->buf;
        append_i->next = target_chain_node->next->next;
    }

    if (append_i->buf) {
        *link_i = append_i;
        link_i = &append_i->next;
    }


    // https://hg.nginx.org/njs/file/77e4b95109d4/nginx/ngx_stream_js_module.c#l585
    // https://mailman.nginx.org/pipermail/nginx-devel/2022-January/6EUIJQXVFHMRZP3L5SJNWPJKQPROWA7U.html

    for (ngx_chain_t *ln = chain; ln != NULL; ln = ln->next) {
        ln->buf->pos = ln->buf->last;
        if (ln == target_chain_node) {
            break;
        }
    }

    ctx->out = chain_out;

chain_update:
    rc = ngx_stream_next_filter(s, ctx->out, from_upstream);

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "pass to next filter after minecraft packet filter, get rc: %d", rc);
#endif

    ngx_chain_update_chains(c->pool,
                            &ctx->free_chain,
                            &ctx->busy_chain,
                            &ctx->out,
                            (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module);

    if (ctx->state == _MC_HANDSHAKE_STATUS_STATE_) {
        if (sconf->replace_on_ping) {
            switch (rc) {
                case NGX_OK:
                    goto end_of_filter;
                case NGX_AGAIN:
                    return rc;
                case NGX_ERROR:
                default:
                    goto filter_failure;
            }
        } else {
            goto filter_failure;
        }
    }

end_of_filter:
    rc = ctx->fail ? NGX_ERROR : rc;
    if (ctx->fail) {
        if (!ctx->pinged) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "Filter failed");
        }
    }
    remove_module_ctx(s);
    return rc;

filter_failure:
    ctx->fail = 1;
    goto end_of_filter;
}

#if (NGX_PCRE)
ngx_regex_t *ngx_stream_minecraft_forward_module_srv_hostname_check_regex = NULL;
#endif

static ngx_int_t ngx_stream_minecraft_forward_module_pre_init(ngx_conf_t *cf) {
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

    ngx_stream_minecraft_forward_module_srv_hostname_check_regex = rc.regex;
#endif
    return NGX_OK;
}

static ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf) {

    ngx_stream_handler_pt       *hp;
    ngx_stream_core_main_conf_t *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    hp = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (hp == NULL) {
        return NGX_ERROR;
    }
    *hp = ngx_stream_minecraft_forward_module_preread;

    ngx_stream_next_filter = ngx_stream_top_filter;
    ngx_stream_top_filter = ngx_stream_minecraft_forward_module_content_filter;

    return NGX_OK;
}
