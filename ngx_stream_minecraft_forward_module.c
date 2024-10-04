#include "ngx_stream_minecraft_forward_module.h"
#include "./protocol/packet.h"
#include "./utils/varint.h"
#include "./utils/packet.h"
#include "./utils/hostname.h"
#include "./protocol/protocol_number.h"

typedef struct {
    ngx_hash_t             hostname_map;
    ngx_hash_init_t        hostname_map_init;
    ngx_hash_keys_arrays_t hostname_map_keys; /* Both `key` and `value` are `ngx_str_t *` */
    size_t                 hash_max_size;
    size_t                 hash_bucket_size;

    ngx_flag_t             replace_on_ping;
    ngx_flag_t             disconnect_on_nomatch;
    ngx_flag_t             enabled;
} ngx_stream_minecraft_forward_module_srv_conf_t;

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

void remove_session_context(ngx_stream_session_t *s);

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s);

ngx_str_t *get_new_hostname_str(ngx_stream_minecraft_forward_module_srv_conf_t *sconf, u_char *buf, size_t len);

static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in, ngx_uint_t from_upstream);
static ngx_int_t ngx_stream_minecraft_forward_module_client_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in);
static ngx_int_t ngx_stream_minecraft_forward_module_upstream_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in);

static ngx_int_t ngx_stream_minecraft_forward_module_pre_init(ngx_conf_t *cf);
static ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf);

ngx_stream_filter_pt ngx_stream_next_filter;

#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_MAX_SIZE_ 512
#define _NGX_STREAM_MC_FORWARD_MODULE_DEFAULT_HASH_BUCKET_SIZE_ 64

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
    ngx_int_t   rc;
    ngx_str_t  *values;
    ngx_str_t  *key;
    ngx_str_t  *val;

    ngx_stream_minecraft_forward_module_srv_conf_t *sc = conf;

    values = cf->args->elts;

    key = &values[1];
    val = &values[2];

    if (cf->args->nelts >= 3 + 1) {
        if (ngx_strcmp(values[3].data, "arbitrary") == 0) {
            goto validation_pass;
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

void remove_session_context(ngx_stream_session_t *s) {
    nsmfm_session_context *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "Removing session context");
#endif

    if (ctx) {
        if (ctx->pool) {
            ngx_destroy_pool(ctx->pool);
            ctx->pool = NULL;
        }
        ngx_pfree(s->connection->pool, ctx);
    }

    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_module);
}

ngx_str_t *get_new_hostname_str(ngx_stream_minecraft_forward_module_srv_conf_t *sconf, u_char *buf, size_t len) {
    if (sconf == NULL || buf == NULL) {
        return NULL;
    }

    return (ngx_str_t *)ngx_hash_find(&sconf->hostname_map, ngx_hash_key(buf, len), buf, len);
}

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s) {
    ngx_connection_t                                *c;
    ngx_stream_minecraft_forward_module_srv_conf_t  *sconf;
    nsmfm_session_context                           *ctx;

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
        ctx = ngx_pcalloc(c->pool, sizeof(nsmfm_session_context));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctx->preread_handler = ngx_stream_minecraft_forward_module_handshake_preread;

        ctx->pool = ngx_create_pool(4096, c->log);
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
        remove_session_context(s);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Preread failed");
        return NGX_ERROR;
    }

    return rc;

preread_failure:
    ctx->fail = 1;
    goto end_of_preread;
}

static ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s) {
    ngx_connection_t       *c;
    nsmfm_session_context  *ctx;

    u_char                 *bufpos;
    ngx_int_t               var;
    u_char                  p;

    ngx_flag_t              buffer_remanent;
    int                     byte_len;

    minecraft_handshake    *handshake;

    c = s->connection;
    c->log->action = "prereading minecraft handshake packet";

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    if (!ctx->handshake) {
        ctx->handshake = ngx_pcalloc(ctx->pool, sizeof(minecraft_packet));
        if (!ctx->handshake) {
            return NGX_ERROR;
        }
    }

    bufpos = c->buffer->pos;

    if (ctx->handshake->length.num <= 0) {
        var = receive_packet_length(ctx->handshake, &bufpos, c->buffer->last, &byte_len);
        if (var != NGX_OK) {
            return var;
        }
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, handshake content len: %d", ctx->handshake->length.num);
        ctx->bufpos = bufpos;
    }

    if (!ctx->handshake->content) {
        bufpos = ctx->bufpos;
        var = receive_packet(ctx->handshake, bufpos, c->buffer->last, nsmfm_handshake_packet_init, ctx->pool);
        if (var != NGX_OK) {
            return var;
        }
        if (bufpos[0] != ctx->handshake->id.bytes[0]) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Read unexpected packet id (%d), (%d) is expected", bufpos[0], ctx->handshake->id.bytes[0]);
            return NGX_ERROR;
        }
        bufpos++;
        ctx->bufpos = bufpos;
    }
    handshake = ctx->handshake->content;

    bufpos = ctx->bufpos;
    if (!parse_varint_fill_object(bufpos, &handshake->protocol_number)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read protocol number");
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, protocol number: %d", handshake->protocol_number.num);

    if (!nsmfm_is_known_protocol(handshake->protocol_number)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unknown protocol number: %d", handshake->protocol_number.num);
        return NGX_ERROR;
    }

    bufpos += handshake->protocol_number.byte_len;

    var = retrieve_string(&bufpos, &handshake->server_address, ctx->pool);
    if (var != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read server hostname");
        return var;
    }

    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read hostname: %s", handshake->server_address.content);

    handshake->server_port |= (bufpos[0] << 8);
    handshake->server_port |= bufpos[1];
    bufpos += _MC_PORT_LEN_;

    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read remote port: %d", handshake->server_port);

    fill_varint_object(bufpos[0], &handshake->next_state);

    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read next state: %d", handshake->next_state.num);

    switch (handshake->next_state.num) {
        case _MC_HANDSHAKE_STATUS_STATE_:
            ctx->preread_handler = NULL;
            ctx->preread_pass = true;

            ctx->in = ngx_alloc_chain_link(ctx->pool);

            if (!ctx->in) {
                return NGX_ERROR;
            }

            buffer_remanent = c->buffer->last - c->buffer->start
                > (ssize_t)(ctx->handshake->length.byte_len + ctx->handshake->length.num);

            byte_len = buffer_remanent ?
                (c->buffer->last - c->buffer->start) : (ctx->handshake->length.byte_len + ctx->handshake->length.num);

            ctx->in->buf = ngx_create_temp_buf(ctx->pool, byte_len);
            if (!ctx->in->buf) {
                return NGX_ERROR;
            }

            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, ctx->handshake->length.bytes, ctx->handshake->length.byte_len);
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, ctx->handshake->id.bytes, ctx->handshake->id.byte_len);
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, handshake->protocol_number.bytes, handshake->protocol_number.byte_len);
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, handshake->server_address.len.bytes, handshake->server_address.len.byte_len);
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, handshake->server_address.content, handshake->server_address.len.num);
            p = (handshake->server_port & 0xFF00) >> 8;
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, &p, 1);
            p = (handshake->server_port & 0x00FF);
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, &p, 1);
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last, handshake->next_state.bytes, handshake->next_state.byte_len);

#if (NGX_DEBUG)
            ngx_log_debug6(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "handshake length byte_len: %d, "
                           "id byte_len: %d, "
                           "protocol_number byte_len: %d, "
                           "server_address byte_len: %d, "
                           "server_address len: %d, "
                           "next_state byte_len: %d",
                           ctx->handshake->length.byte_len,
                           ctx->handshake->id.byte_len,
                           handshake->protocol_number.byte_len,
                           handshake->server_address.len.byte_len,
                           handshake->server_address.len,
                           handshake->next_state.byte_len);
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "buf len: %d", ngx_buf_size(ctx->in->buf));
#endif

            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "Preread: Protocol number: %d, "
                          "Hostname provided: %s, "
                          "Next state: %d",
                          handshake->protocol_number.num,
                          handshake->server_address.content,
                          handshake->next_state.num);

            if (buffer_remanent) {
                ctx->in->buf->last = ngx_cpymem(ctx->in->buf->last,
                    c->buffer->start + (ctx->handshake->length.byte_len + ctx->handshake->length.num),
                    (c->buffer->last - c->buffer->start) - (ctx->handshake->length.byte_len + ctx->handshake->length.num)
                );
#if (NGX_DEBUG)
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "buf len: %d", ngx_buf_size(ctx->in->buf));
#endif
            }

            ctx->in->buf->last_buf = 1;
            ctx->in->next = NULL;

            return NGX_OK;
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            ctx->preread_handler = ngx_stream_minecraft_forward_module_loginstart_preread;
            bufpos++;
            ctx->bufpos = bufpos;
            break;
        case _MC_HANDSHAKE_TRANSFER_STATE_:
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Transfer state is not accepted");
            return NGX_ERROR;
        default:
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unknown next state (%d)", *bufpos);
            return NGX_ERROR;
    }

    return NGX_AGAIN;
}

static ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s) {
    ngx_connection_t        *c;
    nsmfm_session_context   *ctx;

    u_char                  *bufpos;
    ngx_int_t                var;
    int                      byte_len;
    u_char                  *uuid;

    minecraft_handshake     *handshake;
    minecraft_loginstart    *loginstart;

    c = s->connection;
    c->log->action = "prereading minecraft loginstart packet";

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    handshake = ctx->handshake->content;

    if (!ctx->loginstart) {
        ctx->loginstart = ngx_pcalloc(ctx->pool, sizeof(minecraft_packet));
        if (!ctx->loginstart) {
            return NGX_ERROR;
        }
    }

    bufpos = ctx->bufpos;

    if (ctx->loginstart->length.num <= 0) {
        var = receive_packet_length(ctx->loginstart, &bufpos, c->buffer->last, &byte_len);
        if (var != NGX_OK) {
            return var;
        }
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, loginstart content len: %d", ctx->loginstart->length.num);
        ctx->bufpos = bufpos;
    }

    if (!ctx->loginstart->content) {
        bufpos = ctx->bufpos;
        var = receive_packet(ctx->loginstart, bufpos, c->buffer->last, nsmfm_loginstart_packet_init , ctx->pool);
        if (var != NGX_OK) {
            return var;
        }
        if (bufpos[0] != ctx->loginstart->id.bytes[0]) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unexpected packet id (%d), %d is expected", bufpos[0], ctx->loginstart->id.bytes[0]);
            return NGX_ERROR;
        }
        bufpos++;
        ctx->bufpos = bufpos;
    }
    loginstart = ctx->loginstart->content;

    bufpos = ctx->bufpos;
    var = retrieve_string(&bufpos, &loginstart->username, ctx->pool);
    if (var != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read username");
        return var;
    }

    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read username: %s", loginstart->username.content);

    if (handshake->protocol_number.num >= MINECRAFT_1_19_3) {
        uuid = loginstart->uuid;
        if (handshake->protocol_number.num <= MINECRAFT_1_20_1) {
            bufpos += 1;
        }

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
        uuid[_MC_UUID_LITERAL_LEN_] = 0;

        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read uuid: %s", uuid);

        bufpos += _MC_UUID_BYTE_LEN_;
    }

    ctx->in = ngx_alloc_chain_link(ctx->pool);
    if (!ctx->in) {
        return NGX_ERROR;
    }

    ctx->in->buf = ngx_create_temp_buf(ctx->pool,
        ctx->handshake->length.byte_len + ctx->handshake->length.num +
        ctx->loginstart->length.byte_len + ctx->loginstart->length.num);

    if (!ctx->in->buf) {
        return NGX_ERROR;
    }

    ctx->in->buf->last = ngx_cpymem(
        ctx->in->buf->pos,
        c->buffer->pos,
        ctx->handshake->length.byte_len + ctx->handshake->length.num +
        ctx->loginstart->length.byte_len + ctx->loginstart->length.num
    );

    ctx->in->buf->last_buf = 1;
    ctx->in->next = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Preread: Protocol number: %d, "
                  "Hostname provided: %s, "
                  "Username: %s, "
                  "UUID: %s, "
                  "Next state: %d",
                  handshake->protocol_number.num,
                  handshake->server_address.content,
                  loginstart->username.content,
                  handshake->protocol_number.num >= MINECRAFT_1_19_3 ? loginstart->uuid : (u_char *)"*None*",
                  handshake->next_state.num);

    ctx->preread_pass = true;
    return NGX_OK;
}

static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in, ngx_uint_t from_upstream) {
    ngx_connection_t       *c;
    nsmfm_session_context  *ctx;

    c = s->connection;

    if (c->type != SOCK_STREAM || chain_in == NULL) {
        return ngx_stream_next_filter(s, chain_in, from_upstream);
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        return ngx_stream_next_filter(s, chain_in, from_upstream);
    }

    if (from_upstream) {
        return ngx_stream_minecraft_forward_module_upstream_content_filter(s, chain_in);
    } else {
        return ngx_stream_minecraft_forward_module_client_content_filter(s, chain_in);
    }
}

static ngx_int_t ngx_stream_minecraft_forward_module_upstream_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_connection_t       *c;
    ngx_int_t               rc;
    nsmfm_session_context  *ctx;
    minecraft_handshake    *old_handshake;

    c = s->connection;

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Response from upstream");
#endif
    rc = ngx_stream_next_filter(s, chain_in, 1);

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    if (ctx->pinged) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because already used for pinging");
        remove_session_context(s);
        return NGX_ERROR;
    }

    old_handshake = ctx->handshake->content;

    if (old_handshake->next_state.num == _MC_HANDSHAKE_STATUS_STATE_) {
        if (rc == NGX_OK) {
            ctx->pinged = true;
        }
    }
    return rc;
}

static ngx_int_t ngx_stream_minecraft_forward_module_client_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain_in) {
    ngx_connection_t                               *c;
    ngx_int_t                                       rc;
    nsmfm_session_context                          *ctx;
    ngx_stream_minecraft_forward_module_srv_conf_t *sconf;

    minecraft_handshake                            *old_handshake;
    int                                             old_handshake_len; /* This includes varint byte len */
    minecraft_varint                                new_handshake_content_len;

    minecraft_string                                new_hostname;
    minecraft_varint                                protocol_number;

    ngx_str_t                                      *str;
    u_char                                          pchar;

    int                                             in_buf_len;
    int                                             gathered_buf_len;
    ngx_chain_t                                    *target_chain_node;
    int                                             split_remnant_len;
    ngx_chain_t                                    *new_chain;
    ngx_chain_t                                    *split_remnant_chain;

    ngx_chain_t                                    *chain_out;
    ngx_chain_t                                   **link_i;
    ngx_chain_t                                    *append_i;

    c = s->connection;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    old_handshake = ctx->handshake->content;

    c->log->action = "filtering minecraft packet";

    sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Request from client");
#endif
    if (ctx->pinged) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    if (!sconf->replace_on_ping && old_handshake->next_state.num != _MC_HANDSHAKE_LOGINSTART_STATE_) {
        return ngx_stream_next_filter(s, chain_in, 0);
    }

    if (ctx->out) {
        goto chain_update;
    }

    switch (old_handshake->next_state.num) {
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

    protocol_number = old_handshake->protocol_number;

    str = NULL;
    if (sconf->replace_on_ping) {
        str = get_new_hostname_str(sconf, old_handshake->server_address.content, old_handshake->server_address.len.num);
    }
    if (str == NULL) {
        if (sconf->disconnect_on_nomatch) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because of no hostname match");
            goto filter_failure;
        }
        new_hostname = old_handshake->server_address;
    } else {
        new_hostname.content = str->data;
        fill_varint_object(str->len, &new_hostname.len);
    }
    if (new_hostname.len.num <= 0) {
        goto filter_failure;
    }

    // https://wiki.vg/Protocol#Handshake
    // Packet id, Protocol Version varint, Prefixed string (Length varint + content), Server port, Next state.
    rc = 1 + protocol_number.byte_len + new_hostname.len.byte_len + new_hostname.len.num + _MC_PORT_LEN_ + 1;
    fill_varint_object(rc, &new_handshake_content_len);

    old_handshake_len = ctx->handshake->length.byte_len + ctx->handshake->length.num;

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "old_handshake_len (including varint): %d, "
                  "new_handshake_len (content): %d",
                  old_handshake_len,
                  new_handshake_content_len.num);
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
                ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Incomplete chain of buffer. Expected %d, gathered %d", old_handshake_len, gathered_buf_len);
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

    new_chain->buf->pos = ngx_pnalloc(c->pool, (new_handshake_content_len.num + new_handshake_content_len.byte_len) * sizeof(u_char));
    if (new_chain->buf->pos == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain buf space");
        goto filter_failure;
    }

    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start + (new_handshake_content_len.num + new_handshake_content_len.byte_len);
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_handshake_content_len.bytes, new_handshake_content_len.byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, ctx->handshake->id.bytes, ctx->handshake->id.byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, protocol_number.bytes, protocol_number.byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname.len.bytes, new_hostname.len.byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname.content, new_hostname.len.num);
    pchar = (old_handshake->server_port & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);
    pchar = (old_handshake->server_port & 0x00FF);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pchar, 1);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, old_handshake->next_state.bytes, old_handshake->next_state.byte_len);

#if (NGX_DEBUG)
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "new_handshake content len: %d, "
                   "protocol number: %d, "
                   "new_hostname len: %d",
                   new_handshake_content_len.num,
                   old_handshake->protocol_number.num,
                   new_hostname.len.num);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "split_remnant_len: %d", split_remnant_len);
#endif

    if (split_remnant_len > 0) {
        split_remnant_chain = ngx_chain_get_free_buf(c->pool, &ctx->free_chain);
        if (split_remnant_chain == NULL) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant chain");
            goto filter_failure;
        }

        split_remnant_chain->buf->pos = ngx_pnalloc(c->pool, split_remnant_len * sizeof(u_char));
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
                  "Filter: Provided hostname: %s, "
                  "New hostname string: %s",
                  old_handshake->server_address.content,
                  new_hostname.content);


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

    if (append_i->buf != NULL) {
        *link_i = append_i;
        link_i = &append_i->next;
    }

    // https://hg.nginx.org/njs/file/77e4b95109d4/nginx/ngx_stream_js_module.c#l585
    // https://mailman.nginx.org/pipermail/nginx-devel/2022-January/6EUIJQXVFHMRZP3L5SJNWPJKQPROWA7U.html

    for (ngx_chain_t *ln = chain_in; ln != NULL; ln = ln->next) {
        ln->buf->pos = ln->buf->last;
        if (ln == target_chain_node) {
            break;
        }
    }
    ngx_free_chain(c->pool, target_chain_node);

    ctx->out = chain_out;

chain_update:
    rc = ngx_stream_next_filter(s, ctx->out, 0);

#if (NGX_DEBUG)
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "pass to next filter after minecraft packet filter, get rc: %d", rc);
#endif

    ngx_chain_update_chains(c->pool,
                            &ctx->free_chain,
                            &ctx->busy_chain,
                            &ctx->out,
                            (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module);

    if (old_handshake->next_state.num == _MC_HANDSHAKE_STATUS_STATE_) {
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
    remove_session_context(s);
    return rc;

filter_failure:
    ctx->fail = 1;
    goto end_of_filter;
}

#if (NGX_PCRE)
ngx_regex_t *nsmfm_validate_hostname_regex = NULL;
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

    nsmfm_validate_hostname_regex = rc.regex;
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
