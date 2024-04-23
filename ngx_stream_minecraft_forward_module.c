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

#define NGX_STREAM_MC_FORWARD_MODULE_DEF_HASH_MAX_SIZE 512
#define NGX_STREAM_MC_FORWARD_MODULE_DEF_HASH_BUCKET_SIZE 64
#define _NGX_MC_FORWARD_SRV_CTX_POOL_SIZE_ 1024
#define _NGX_MC_STATE_STATUS_ 1
#define _NGX_MC_STATE_LOGIN_ 2
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
                           "Invalid entry: %s", key->data ? key->data : (u_char *)"*NULL*");
        return NGX_CONF_ERROR;
    }
    if (ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(val) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Invalid value: %s", val->data ? val->data : (u_char *)"*NULL*");
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
        NGX_CONF_UNSET_SIZE, NGX_STREAM_MC_FORWARD_MODULE_DEF_HASH_MAX_SIZE);

    ngx_conf_merge_size_value(pconf->hash_bucket_size,
        NGX_CONF_UNSET_SIZE, NGX_STREAM_MC_FORWARD_MODULE_DEF_HASH_BUCKET_SIZE);

    ngx_conf_merge_size_value(cconf->hash_max_size,
        pconf->hash_max_size, NGX_STREAM_MC_FORWARD_MODULE_DEF_HASH_MAX_SIZE);

    ngx_conf_merge_size_value(cconf->hash_bucket_size,
        pconf->hash_bucket_size, NGX_STREAM_MC_FORWARD_MODULE_DEF_HASH_BUCKET_SIZE);

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
                               "A hash key previously in stream context becomes missing?!"
                               " This should not happen");
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

static void remove_module_ctx(ngx_stream_session_t *s) {
    ngx_stream_minecraft_forward_ctx_t *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    if (ctx) {
        ctx->out = NULL;

        if (ctx->pool) {
            ngx_destroy_pool(ctx->pool);
            ctx->pool = NULL;
        }

        ngx_pfree(s->connection->pool, ctx);
    }

    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_module);
}

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s) {
    ngx_connection_t                               *c;
    ngx_stream_minecraft_forward_module_srv_conf_t *sconf;
    ngx_stream_minecraft_forward_ctx_t             *ctx;

    ngx_int_t                                       rc;

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

        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_minecraft_forward_module));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctx->preread_handler = ngx_stream_minecraft_forward_module_handshake_preread;
        ctx->preread_pass = 0;
        ctx->pinged = 0;
        ctx->fail = 0;

        ctx->protocol_num = -1;

        ctx->handshake_len = 0;
        ctx->protocol_num_varint.data = NULL;
        ctx->protocol_num_varint.len = 0;
        ctx->expected_packet_len = 0;
        ctx->handshake_varint_byte_len = 0;
        ctx->provided_hostname_varint_byte_len = 0;

        ctx->pool = ngx_create_pool(_NGX_MC_FORWARD_SRV_CTX_POOL_SIZE_, c->log);
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

    return rc;

end_of_preread:
    if (ctx->fail) {
        remove_module_ctx(s);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Preread failed");
        return NGX_ERROR;
    }

    ctx->preread_pass = 1;
    return NGX_OK;

preread_failure:
    ctx->fail = 1;
    goto end_of_preread;
}

static ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s) {
    ngx_connection_t                                *c;
    ngx_stream_minecraft_forward_ctx_t              *ctx;

    u_char                                          *bufpos;
    u_char                                          *buflast;

#if (nginx_version >= 1025005)
    ngx_stream_minecraft_forward_module_srv_conf_t  *sconf;
    size_t                                           bufsize;

    sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);
#endif
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    c = s->connection;

    bufpos = c->buffer->pos;
    buflast = c->buffer->last;

    c->log->action = "prereading minecraft handshake packet";

    if (!ctx->handshake_varint_byte_len) {
        bufpos = parse_packet_length(s, bufpos, &ctx->handshake_varint_byte_len);
    } else {
        bufpos += ctx->handshake_varint_byte_len;
    }

    if (!bufpos) {
        if (buflast - c->buffer->pos < _MC_VARINT_MAX_BYTE_LEN_) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    if (!ctx->handshake_len) {
        ctx->handshake_len = ctx->expected_packet_len;
    }

    if ((size_t)(buflast - bufpos) < ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (*(bufpos++) != _PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        return NGX_ERROR;
    }

    if (!ctx->protocol_num_varint.data) {
        ctx->protocol_num = read_minecraft_varint(bufpos, &ctx->protocol_num_varint.len);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "read varint, protocol num: %d", ctx->protocol_num);

        if (is_protocol_num_acceptable_by_ctx(ctx) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Protocol number %d is not acceptable", ctx->protocol_num);
            return NGX_ERROR;
        }

        ctx->protocol_num_varint.data = bufpos;
    }

    bufpos += ctx->protocol_num_varint.len;

    if (!ctx->provided_hostname_varint_byte_len) {
        ctx->provided_hostname.len = read_minecraft_varint(bufpos, &ctx->provided_hostname_varint_byte_len);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "read varint, provided host string len: %d", ctx->provided_hostname.len);

        if (ctx->provided_hostname.len <= 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "There's a problem getting host string length (%d)", ctx->provided_hostname.len);
            return NGX_ERROR;
        }
    }

    bufpos += ctx->provided_hostname_varint_byte_len;

    if (ctx->provided_hostname.data == NULL) {
        ctx->provided_hostname.data =
            parse_string_from_packet(ctx->pool, bufpos, ctx->provided_hostname.len);

        if (ctx->provided_hostname.data == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot retrieve hostname");
            return NGX_ERROR;
        }
    }

    bufpos += ctx->provided_hostname.len;

    ctx->remote_port |= (bufpos[0] << 8);
    ctx->remote_port |= bufpos[1];

    bufpos += _MINECRAFT_PORT_LEN_;

#if (nginx_version >= 1025005)

    if (sconf->replace_on_ping || *bufpos == _NGX_MC_STATE_LOGIN_) {

        bufsize =
            *bufpos == _NGX_MC_STATE_LOGIN_ ?
                (ctx->handshake_varint_byte_len + ctx->handshake_len) : (size_t)(buflast - c->buffer->pos);

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Storing handshake");

        if (!ctx->in) {
            ctx->in = ngx_alloc_chain_link(c->pool);

            if (ctx->in == NULL) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                              "Cannot get free buf chain to store provided handshake");
                return NGX_ERROR;
            }

            ctx->in->buf = ngx_create_temp_buf(ctx->pool, bufsize);
            if (ctx->in->buf == NULL) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                              "Cannot initialize buf memory space to store provided handshake");
                return NGX_ERROR;
            }

            ctx->in->next = NULL;
            ctx->in->buf->last = ngx_cpymem(ctx->in->buf->pos, c->buffer->pos, bufsize);
            ctx->in->buf->memory = 1;
            ctx->in->buf->last_buf = 1;
            ctx->in->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
        }
    }

#endif

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "Preread: handshake_varint_byte_len: %d, handshake_len: %d",
                   ctx->handshake_varint_byte_len,
                   ctx->handshake_len);

    if (*bufpos == _NGX_MC_STATE_STATUS_) {

        ctx->preread_handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "Preread: Protocol num: %d, "
                      "Hostname provided: %s, "
                      "Next state: %d",
                      ctx->protocol_num,
                      ctx->provided_hostname.data ? ctx->provided_hostname.data : (u_char *)"*Missing*",
                      *bufpos);

        ctx->state = _NGX_MC_STATE_STATUS_;

        return NGX_OK;

    } else if (*bufpos == _NGX_MC_STATE_LOGIN_) {

        ctx->preread_handler = ngx_stream_minecraft_forward_module_loginstart_preread;
        ctx->state = _NGX_MC_STATE_LOGIN_;

    } else {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Unknown next state (%d)", *bufpos);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Preread: Protocol num: %d, "
                  "Hostname provided: %s, "
                  "Next state: %d",
                  ctx->protocol_num,
                  ctx->provided_hostname.data ? ctx->provided_hostname.data : (u_char *)"*Missing*",
                  ctx->state);

    return NGX_AGAIN;
}

static ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s) {
    ngx_connection_t                    *c;
    ngx_stream_minecraft_forward_ctx_t  *ctx;

    u_char                              *bufpos;
    u_char                              *buflast;

    u_char                              *h_pos;

#if (nginx_version >= 1025005)
    size_t                               bufsize;
    ngx_buf_t                           *inbuf;
    ngx_chain_t                         *chain;
#endif

    c = s->connection;

    c->log->action = "prereading minecraft loginstart packet";

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    h_pos = c->buffer->pos + ctx->handshake_len + ctx->handshake_varint_byte_len;
    buflast = c->buffer->last;
    bufpos = h_pos;

    bufpos = parse_packet_length(s, bufpos, &ctx->loginstart_varint_byte_len);
    if (bufpos == NULL) {
        if (buflast - h_pos < _MC_VARINT_MAX_BYTE_LEN_) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    if ((size_t)(buflast - bufpos) < ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (*(bufpos++) != _PACKET_ID_) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "Unexpected packet id (%d), 0x00 is expected", *bufpos);
        return NGX_ERROR;
    }

    ctx->loginstart_len = ctx->expected_packet_len;

    if (!ctx->username_varint_byte_len) {
        ctx->username.len = read_minecraft_varint(bufpos, &ctx->username_varint_byte_len);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "read varint, username len: %d", ctx->username.len);

        if (ctx->username.len <= 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "There's a problem getting username string length (%d)", ctx->username.len);
            return NGX_ERROR;
        }
        if (ctx->username.len > 16) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Username too long (%d)", ctx->username.len);
            return NGX_ERROR;
        }
    }

    bufpos += ctx->username_varint_byte_len;

    if (!ctx->username.data) {
        ctx->username.data = parse_string_from_packet(ctx->pool, bufpos, ctx->username.len);

        if (ctx->username.data == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot retrieve username");
            return NGX_ERROR;
        }
    }

    bufpos += ctx->username.len;

    if (ctx->protocol_num >= MINECRAFT_1_19_3) {
        if (ctx->protocol_num <= MINECRAFT_1_20_1) {
            ++bufpos;
        }

        ctx->uuid.data = ngx_pcalloc(ctx->pool, (_UUID_LEN_ + 1) * sizeof(u_char));
        ctx->uuid.len = _UUID_LEN_;

        if (ctx->uuid.data == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Cannot retrieve UUID");
        } else {
            for (int i = 0; i < _UUID_LEN_; ++i) {

                ctx->uuid.data[i] = i % 2 ? (bufpos[i / 2] & (u_char)0x0F) : ((bufpos[i / 2] & (u_char)0xF0) >> 4);

                if (ctx->uuid.data[i] <= 9) {

                    ctx->uuid.data[i] += '0';

                } else if (ctx->uuid.data[i] >= 10 && ctx->uuid.data[i] <= 15) {

                    ctx->uuid.data[i] = 'a' + (ctx->uuid.data[i] - 10);

                } else {
                    return NGX_ERROR;
                }
            }
        }

        bufpos += _UUID_LEN_ / 2;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Preread: Protocol num: %d, "
                  "Hostname provided: %s, "
                  "Username: %s, "
                  "UUID: %s, ",
                  ctx->protocol_num,
                  ctx->provided_hostname.data ? ctx->provided_hostname.data : (u_char *)"*Missing*",
                  ctx->username.data ? ctx->username.data : (u_char *)"*Missing*",
                  ctx->uuid.data ? ctx->uuid.data : (u_char *)"*Missing*");

#if (nginx_version >= 1025005)

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "Storing loginstart");

    bufsize = buflast - h_pos;

    chain = ctx->in;

    inbuf = chain->buf;
    inbuf->last_buf = 0;

    chain->next = ngx_alloc_chain_link(c->pool);

    if (chain->next == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                      "Cannot get free buf chain to store provided loginstart packet");
        return NGX_ERROR;
    }

    chain = chain->next;

    chain->buf = ngx_create_temp_buf(ctx->pool, bufsize);
    if (chain->buf == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                      "Cannot initialize buf memory space to store loginstart packet");
        return NGX_ERROR;
    }

    chain->next = NULL;
    inbuf = chain->buf;

    inbuf->memory = 1;
    inbuf->last_buf = 1;
    inbuf->last = ngx_cpymem(inbuf->pos, h_pos, bufsize);
    inbuf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;

#endif

    return NGX_OK;
}

static ngx_str_t *get_new_hostname_str(ngx_stream_minecraft_forward_module_srv_conf_t *sconf, ngx_str_t old_str) {
    if (!sconf || !old_str.data) {
        return NULL;
    }

    return (ngx_str_t *)ngx_hash_find(&sconf->hostname_map, ngx_hash_key(old_str.data, old_str.len),
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

    u_char                                         *bufpos;
    u_char                                          pid_char;
    u_char                                          port_char;
    u_char                                          state_char;

    size_t                                          in_buf_len;
    size_t                                          gathered_buf_len;
    ngx_chain_t                                    *target_chain_node;
    size_t                                          split_remnant_len;
    ngx_chain_t                                    *new_chain;
    ngx_chain_t                                    *split_remnant_chain;

    ngx_chain_t                                    *chain_in;
    ngx_chain_t                                    *chain_out;
    ngx_chain_t                                   **link_i;
    ngx_chain_t                                    *append_i;

    c = s->connection;

    if (c->type != SOCK_STREAM || chain == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    c->log->action = "filtering minecraft packet";

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    if (ctx->pinged) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Closing connection because already used for pinging");
        goto filter_failure;
    }

    sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);

    if (from_upstream) {
        if (ctx->state == _NGX_MC_STATE_STATUS_) {

            bufpos = parse_packet_length(s, c->buffer->pos, NULL);

            if (bufpos == NULL) {
                if (c->buffer->last - c->buffer->pos < _MC_VARINT_MAX_BYTE_LEN_) {
                    return NGX_AGAIN;
                }
                return NGX_ERROR;
            }

            if ((size_t)(c->buffer->last - bufpos) < ctx->expected_packet_len) {
                return NGX_AGAIN;
            }

            if (!ctx->pinged) {
                ctx->pinged = 1;
            }
        }
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    if (!sconf->replace_on_ping && ctx->state != _NGX_MC_STATE_LOGIN_) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    switch (ctx->state) {
        case _NGX_MC_STATE_LOGIN_:
            c->log->action = "filtering and forwarding new minecraft loginstart packet";
            break;
        case _NGX_MC_STATE_STATUS_:
            c->log->action = "filtering and forwarding minecraft ping packet";
            break;
        default:
            c->log->action = "filtering minecraft packet";
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "UNKNOWN STATE in filter");
            goto filter_failure;
    }

    if (ctx->out != NULL) {
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

    protocol_num_varint = ctx->protocol_num_varint.data;
    protocol_varint_byte_len = ctx->protocol_num_varint.len;

    new_hostname = get_new_hostname_str(sconf, ctx->provided_hostname);
    if (new_hostname == NULL) {
        if (sconf->disconnect_on_nomatch) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "Closing connection because of no hostname match");
            goto filter_failure;
        }

        new_hostname_str = ctx->provided_hostname.data;
        new_hostname_str_len = ctx->provided_hostname.len;
    } else {
        new_hostname_str = new_hostname->data;
        new_hostname_str_len = new_hostname->len;
    }
    if (new_hostname_str_len <= 0) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Empty hostname string");
        goto filter_failure;
    }

    new_hostname_varint_bytes = create_minecraft_varint(ctx->pool, new_hostname_str_len, &new_hostname_varint_byte_len);
    if (new_hostname_varint_bytes == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot create new hostname varint of length");
        goto filter_failure;
    }

    // https://wiki.vg/Protocol#Handshake
    // Packet id, Protocol Version varint, Prefixed string (Length varint + content), Server port, Next state.
    new_handshake_len =
        1 +
        protocol_varint_byte_len +
        new_hostname_varint_byte_len +
        new_hostname_str_len +
        _MINECRAFT_PORT_LEN_ +
        1;

    // The whole packet is prefixed by a total length in varint.
    new_handshake_varint_bytes = create_minecraft_varint(ctx->pool, new_handshake_len, &new_handshake_varint_byte_len);
    if (new_handshake_varint_bytes == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot create new handshake packet varint of length");
        goto filter_failure;
    }

    old_handshake_len = ctx->handshake_varint_byte_len + ctx->handshake_len;
    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "old_handshake_len (including varint bytes): %d, new_handshake_len: %d",
                   old_handshake_len, new_handshake_len);

    new_handshake_len = new_handshake_varint_byte_len + new_handshake_len;
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "new_handshake_len (including varint bytes): %d", new_handshake_len);

    target_chain_node = NULL;

    in_buf_len = 0;
    gathered_buf_len = 0;

    chain_in = chain;

#if (nginx_version >= 1025005)
    if (ctx->in != NULL) {
        chain_in = ctx->in;
    }
#endif

    for (ngx_chain_t *ln = chain_in; ln != NULL; ln = ln->next) {

        // https://hg.nginx.org/nginx/rev/cf890df37bb6

        in_buf_len = ngx_buf_size(ln->buf);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "in_buf_len: %d", in_buf_len);

        if (in_buf_len <= 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "negative size of or empty buffer encountered");
            goto filter_failure;
        }

        gathered_buf_len += in_buf_len;
        if (ln->buf->last_buf) {
            if (gathered_buf_len < old_handshake_len) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "Incomplete chain of buffer");
                goto filter_failure;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "gathered_buf_len: %d", gathered_buf_len);

        if (gathered_buf_len >= old_handshake_len) {
            target_chain_node = ln;
            break;
        }
    }

    // https://wiki.vg/Protocol#Status_Request

    split_remnant_len = gathered_buf_len - old_handshake_len;
    split_remnant_chain = NULL;

    new_chain = ngx_chain_get_free_buf(c->pool, &ctx->free_chain);
    if (new_chain == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot get free buf chain to store new handshake");
        goto filter_failure;
    }

    new_chain->buf->pos = ngx_pcalloc(c->pool, new_handshake_len * sizeof(u_char));
    if (new_chain->buf->pos == NULL) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize new chain buf space");
        goto filter_failure;
    }

    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start + (new_handshake_len * sizeof(u_char));
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->pos, new_handshake_varint_bytes, new_handshake_varint_byte_len);

    // Packet id 0x00
    pid_char = _PACKET_ID_;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &pid_char, 1);

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, protocol_num_varint, protocol_varint_byte_len);

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_varint_bytes, new_hostname_varint_byte_len);

    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_str, new_hostname_str_len);

    port_char = (ctx->remote_port & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &port_char, 1);
    port_char = ctx->remote_port & 0x00FF;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &port_char, 1);

    state_char = ctx->state;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &state_char, 1);

    ngx_log_debug5(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "new_handshake_varint_byte_len: %d, "
                   "ctx protocol_num: %d, "
                   "protocol_varint_byte_len: %d, "
                   "new_hostname_varint_byte_len: %d, "
                   "new_hostname_str_len: %d",
                   new_handshake_varint_byte_len,
                   ctx->protocol_num,
                   protocol_varint_byte_len,
                   new_hostname_varint_byte_len,
                   new_hostname_str_len);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "split_remnant_len: %d", split_remnant_len);

    if (split_remnant_len > 0) {

        split_remnant_chain = ngx_chain_get_free_buf(c->pool, &ctx->free_chain);
        if (split_remnant_chain == NULL) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot get free buf chain for split remnant");
            goto filter_failure;
        }

        split_remnant_chain->buf->pos = ngx_pcalloc(c->pool, split_remnant_len * sizeof(u_char));
        if (split_remnant_chain->buf->pos == NULL) {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Cannot initialize split remnant new buf space");
            goto filter_failure;
        }

        split_remnant_chain->buf->start = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->last = split_remnant_chain->buf->pos;
        split_remnant_chain->buf->end = split_remnant_chain->buf->start + (split_remnant_len * sizeof(u_char));
        split_remnant_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
        split_remnant_chain->buf->memory = 1;

        split_remnant_chain->buf->last = ngx_cpymem(split_remnant_chain->buf->pos,
                                                    target_chain_node->buf->last - split_remnant_len,
                                                    split_remnant_len);
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Filter: Provided hostname: %s, "
                  "New hostname string: %s",
                  ctx->provided_hostname.data,
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

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "passed to next filter after minecraft packet filter, get rc: %d", rc);

    ngx_chain_update_chains(c->pool,
                            &ctx->free_chain,
                            &ctx->busy_chain,
                            &ctx->out,
                            (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module);

    if (ctx->state == _NGX_MC_STATE_STATUS_) {
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
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Filter failed");
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
