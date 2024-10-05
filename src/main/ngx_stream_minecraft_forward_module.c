#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include "ngx_stream_minecraft_forward_module.h"
#include "nsmfm_handler.h"
#include "nsmfm_session.h"
#include "../protocol/nsmfm_packet.h"
#include "../protocol/nsmfm_protocol_number.h"
#include "../utils/nsmfm_varint.h"
#include "../utils/nsmfm_packet.h"
#include "../utils/nsmfm_hostname.h"
#include "../filter/nsmfcfm_session.h"

static void *nsmfm_create_srv_conf(ngx_conf_t *cf);
static char *nsmfm_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static char *nsmfm_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t nsmfm_preread(ngx_stream_session_t *s);
static ngx_int_t nsmfm_handshake_preread(ngx_stream_session_t *s);
static ngx_int_t nsmfm_loginstart_preread(ngx_stream_session_t *s);

static ngx_int_t nsmfm_pre_init(ngx_conf_t *cf);
static ngx_int_t nsmfm_post_init(ngx_conf_t *cf);

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
    nsmfm_post_init, /* postconfiguration */

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

static ngx_int_t nsmfm_preread(ngx_stream_session_t *s) {
    ngx_connection_t       *c;
    nsmfm_srv_conf_t       *sconf;
    nsmfm_session_context  *ctx;

    ngx_int_t               rc;

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

    ctx = nsmfm_get_session_context(s);
    if (ctx == NULL) {
        if (!nsmfm_create_session_context(s)) {
            return NGX_ERROR;
        }
        ctx = nsmfm_get_session_context(s);
        ctx->handler = nsmfm_handshake_preread;
    }

    if (ctx->pass) {
        return NGX_OK;
    }

    rc = ctx->handler(s);

    if (rc == NGX_ERROR) {
        goto preread_failure;
    }

end_of_preread:
    if (ctx->fail) {
        nsmfm_remove_session_context(s);
        nsmfcfm_remove_session_context(s);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Preread failed");
        return NGX_ERROR;
    }

    return rc;

preread_failure:
    ctx->fail = 1;
    goto end_of_preread;
}

static ngx_int_t nsmfm_handshake_preread(ngx_stream_session_t *s) {
    ngx_connection_t         *c;
    nsmfm_session_context    *ctx;
    nsmfcfm_session_context  *cfctx;

    u_char                   *bufpos;
    ngx_int_t                 var;
    u_char                    p;

    ngx_flag_t                buffer_remanent;
    int                       byte_len;

    minecraft_handshake      *handshake;

    c = s->connection;
    c->log->action = "prereading minecraft handshake packet";

    ctx = nsmfm_get_session_context(s);

    if (!ctx->handshake) {
        ctx->handshake = ngx_pcalloc(ctx->pool, sizeof(minecraft_packet));
        if (!ctx->handshake) {
            return NGX_ERROR;
        }
    }

    bufpos = c->buffer->pos;

    if (ctx->handshake->length.num <= 0) {
        var = get_packet_length(ctx->handshake, &bufpos, c->buffer->last, &byte_len);
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
            ctx->handler = NULL;
            ctx->pass = true;

            if (!nsmfcfm_create_session_context(s)) {
                return NGX_ERROR;
            }
            cfctx = nsmfcfm_get_session_context(s);

            cfctx->in = ngx_alloc_chain_link(cfctx->pool);

            if (!cfctx->in) {
                return NGX_ERROR;
            }

            buffer_remanent = c->buffer->last - c->buffer->start
                > (ssize_t)(ctx->handshake->length.byte_len + ctx->handshake->length.num);

            byte_len = buffer_remanent ?
                (c->buffer->last - c->buffer->start) : (ctx->handshake->length.byte_len + ctx->handshake->length.num);

            cfctx->in->buf = ngx_create_temp_buf(cfctx->pool, byte_len);
            if (!cfctx->in->buf) {
                return NGX_ERROR;
            }

            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, ctx->handshake->length.bytes, ctx->handshake->length.byte_len);
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, ctx->handshake->id.bytes, ctx->handshake->id.byte_len);
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, handshake->protocol_number.bytes, handshake->protocol_number.byte_len);
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, handshake->server_address.len.bytes, handshake->server_address.len.byte_len);
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, handshake->server_address.content, handshake->server_address.len.num);
            p = (handshake->server_port & 0xFF00) >> 8;
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, &p, 1);
            p = (handshake->server_port & 0x00FF);
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, &p, 1);
            cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last, handshake->next_state.bytes, handshake->next_state.byte_len);

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
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "buf len: %d", ngx_buf_size(cfctx->in->buf));
#endif

            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "Preread: Protocol number: %d, "
                          "Hostname provided: %s, "
                          "Next state: %d",
                          handshake->protocol_number.num,
                          handshake->server_address.content,
                          handshake->next_state.num);

            if (buffer_remanent) {
                cfctx->in->buf->last = ngx_cpymem(cfctx->in->buf->last,
                    c->buffer->start + (ctx->handshake->length.byte_len + ctx->handshake->length.num),
                    (c->buffer->last - c->buffer->start) - (ctx->handshake->length.byte_len + ctx->handshake->length.num)
                );
#if (NGX_DEBUG)
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "buf len: %d", ngx_buf_size(cfctx->in->buf));
#endif
            }

            cfctx->in->buf->last_buf = 1;
            cfctx->in->next = NULL;

            return NGX_OK;
        case _MC_HANDSHAKE_LOGINSTART_STATE_:
            ctx->handler = nsmfm_loginstart_preread;
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

static ngx_int_t nsmfm_loginstart_preread(ngx_stream_session_t *s) {
    ngx_connection_t         *c;
    nsmfm_session_context    *ctx;
    nsmfcfm_session_context  *cfctx;

    u_char                   *bufpos;
    ngx_int_t                 var;
    int                       byte_len;
    u_char                   *uuid;

    minecraft_handshake      *handshake;
    minecraft_loginstart     *loginstart;

    c = s->connection;
    c->log->action = "prereading minecraft loginstart packet";

    ctx = nsmfm_get_session_context(s);
    if (!nsmfcfm_create_session_context(s)) {
        return NGX_ERROR;
    }
    cfctx = nsmfcfm_get_session_context(s);

    handshake = ctx->handshake->content;

    if (!ctx->loginstart) {
        ctx->loginstart = ngx_pcalloc(ctx->pool, sizeof(minecraft_packet));
        if (!ctx->loginstart) {
            return NGX_ERROR;
        }
    }

    bufpos = ctx->bufpos;

    if (ctx->loginstart->length.num <= 0) {
        var = get_packet_length(ctx->loginstart, &bufpos, c->buffer->last, &byte_len);
        if (var != NGX_OK) {
            return var;
        }
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                      "read varint, loginstart content len: %d", ctx->loginstart->length.num);
        ctx->bufpos = bufpos;
    }

    if (!ctx->loginstart->content) {
        bufpos = ctx->bufpos;
        var = receive_packet(ctx->loginstart, bufpos, c->buffer->last, nsmfm_loginstart_packet_init , ctx->pool);
        if (var != NGX_OK) {
            return var;
        }
        if (bufpos[0] != ctx->loginstart->id.bytes[0]) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Unexpected packet id (%d), %d is expected", bufpos[0], ctx->loginstart->id.bytes[0]);
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

    cfctx->in = ngx_alloc_chain_link(cfctx->pool);
    if (!cfctx->in) {
        return NGX_ERROR;
    }

    cfctx->in->buf = ngx_create_temp_buf(cfctx->pool,
        ctx->handshake->length.byte_len + ctx->handshake->length.num +
        ctx->loginstart->length.byte_len + ctx->loginstart->length.num);

    if (!cfctx->in->buf) {
        return NGX_ERROR;
    }

    cfctx->in->buf->last = ngx_cpymem(
        cfctx->in->buf->pos,
        c->buffer->pos,
        ctx->handshake->length.byte_len + ctx->handshake->length.num +
        ctx->loginstart->length.byte_len + ctx->loginstart->length.num
    );

    cfctx->in->buf->last_buf = 1;
    cfctx->in->next = NULL;

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

    ctx->pass = true;
    return NGX_OK;
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

static ngx_int_t nsmfm_post_init(ngx_conf_t *cf) {
    ngx_stream_handler_pt       *hp;
    ngx_stream_core_main_conf_t *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    hp = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (hp == NULL) {
        return NGX_ERROR;
    }
    *hp = nsmfm_preread;

    return NGX_OK;
}
