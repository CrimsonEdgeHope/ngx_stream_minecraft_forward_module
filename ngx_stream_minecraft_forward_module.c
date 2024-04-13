#include "ngx_stream_minecraft_forward_module.h"
#include "ngx_stream_minecraft_forward_module_utils.h"
#include "ngx_stream_minecraft_protocol_numbers.h"

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

static char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain, ngx_uint_t from_upstream);

static ngx_int_t ngx_stream_minecraft_forward_module_pre_init(ngx_conf_t *cf);
static ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf);

ngx_stream_filter_pt ngx_stream_next_filter;

#define HANDSHAKE_PHASE 1
#define STATUS_PHASE 2
#define LOGIN_START_PHASE 3

#define PORT_LEN sizeof(u_short)

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

    ngx_stream_minecraft_forward_module_srv_conf_t *conf;

    ngx_int_t rc;

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
        ngx_pfree(cf->pool, conf);
        return NULL;
    }

    conf->replace_on_ping = NGX_CONF_UNSET;

    return conf;
}

static char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_stream_minecraft_forward_module_srv_conf_t *sc = conf;

    ngx_str_t *values;
    values = cf->args->elts;
    ngx_int_t rc;

    ngx_str_t *key = &values[1];
    ngx_str_t *val = &values[2];

    ngx_flag_t pass = 0;
    if (cf->args->nelts >= 3 + 1) {
        if (ngx_strcmp(values[3].data, "arbitrary") == 0) {
            pass = 1;
        }
    }
    if (!pass) {
        if (ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(key) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "Invalid entry: %s", key->data ? key->data : (u_char *)"*NULL*");
            return NGX_CONF_ERROR;
        }
        if (ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(val) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "Invalid value: %s", val->data ? val->data : (u_char *)"*NULL*");
            return NGX_CONF_ERROR;
        }
    }

    rc = ngx_hash_add_key(&sc->hostname_map_keys, key, val, NGX_HASH_READONLY_KEY);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "There's a problem adding hash key, possibly because of duplicate entry");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#define _DEFAULT_HASH_MAX_SIZE 512
#define _DEFAULT_HASH_BUCKET_SIZE 64

static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_stream_minecraft_forward_module_srv_conf_t *pconf = prev;
    ngx_stream_minecraft_forward_module_srv_conf_t *cconf = conf;

    ngx_conf_merge_value(cconf->enabled, pconf->enabled, 0);
    ngx_conf_merge_value(cconf->disconnect_on_nomatch, pconf->disconnect_on_nomatch, 0);
    ngx_conf_merge_value(cconf->replace_on_ping, pconf->replace_on_ping, 1);
    ngx_conf_merge_size_value(pconf->hash_max_size, NGX_CONF_UNSET_SIZE, _DEFAULT_HASH_MAX_SIZE);
    ngx_conf_merge_size_value(pconf->hash_bucket_size, NGX_CONF_UNSET_SIZE, _DEFAULT_HASH_BUCKET_SIZE);
    ngx_conf_merge_size_value(cconf->hash_max_size, pconf->hash_max_size, _DEFAULT_HASH_MAX_SIZE);
    ngx_conf_merge_size_value(cconf->hash_bucket_size, pconf->hash_bucket_size, _DEFAULT_HASH_BUCKET_SIZE);

    pconf->hostname_map_init.max_size = pconf->hash_max_size;
    pconf->hostname_map_init.bucket_size = ngx_align(pconf->hash_bucket_size, ngx_cacheline_size);

    ngx_int_t rc;
    rc = ngx_hash_init(&pconf->hostname_map_init, pconf->hostname_map_keys.keys.elts, pconf->hostname_map_keys.keys.nelts);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "There's a problem initializing hash table in stream context");
        return NGX_CONF_ERROR;
    }

    // MERGE HASH TABLE
    for (ngx_uint_t i = 0; i < pconf->hostname_map_keys.keys.nelts; ++i) {
        ngx_str_t *key = &((ngx_hash_key_t *)pconf->hostname_map_keys.keys.elts + i)->key;

        ngx_uint_t hashed_key = ngx_hash_key(key->data, key->len);

        ngx_str_t *val = (ngx_str_t *)ngx_hash_find(&pconf->hostname_map, hashed_key, key->data, key->len);

        if (val == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "A hash key previously in stream context becomes missing?! This should not happen");
            return NGX_CONF_ERROR;
        }

        rc = ngx_hash_add_key(&cconf->hostname_map_keys, key, val, NGX_HASH_READONLY_KEY);
        if (rc != NGX_OK) {
            if (rc == NGX_BUSY) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "There's a problem merging hash table because of duplicate entry");
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "There's a problem merging hash table");
                return NGX_CONF_ERROR;
            }
        }
    }

    cconf->hostname_map_init.max_size = cconf->hash_max_size;
    cconf->hostname_map_init.bucket_size = ngx_align(cconf->hash_bucket_size, ngx_cacheline_size);
    rc = ngx_hash_init(&cconf->hostname_map_init, cconf->hostname_map_keys.keys.elts, cconf->hostname_map_keys.keys.nelts);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "There's a problem initializing hash table in server context");
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
    ngx_connection_t *c = s->connection;
    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    ngx_stream_minecraft_forward_module_srv_conf_t *sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);
    if (!sconf->enabled) {
        return NGX_DECLINED;
    }
    c->log->action = "prereading minecraft packet";
    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ngx_int_t protocol_num = -1;
    u_char *hostname_str = NULL;
    u_char *username_str = NULL;
    u_char *uuid = NULL;

    ngx_stream_minecraft_forward_ctx_t *ctx;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_minecraft_forward_module));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->phase = HANDSHAKE_PHASE;
        ctx->preread_pass = 0;
        ctx->pinged = 0;
        ctx->remote_hostname = NULL;
        ctx->fail = 0;
        ctx->pool = ngx_create_pool(1024, c->log);
        if (ctx->pool == NULL) {
            goto preread_failure;
        }
        ngx_stream_set_ctx(s, ctx, ngx_stream_minecraft_forward_module);
    }

    if (ctx->preread_pass) {
        return NGX_OK;
    }

    u_char *bufpos = c->buffer->pos;
    u_char *buflast = c->buffer->last;

    if (ctx->phase == HANDSHAKE_PHASE && bufpos[0] == (u_char)'\xFE') { // Legacy ping 0xFE
        goto preread_failure;
    }

    c->log->action = "prereading minecraft handshake packet";

    size_t byte_len = 0;
    size_t prefix_len = 0;
    bufpos = parse_packet_length(s, bufpos, &byte_len);
    if (bufpos == NULL) {
        if (buflast - c->buffer->pos < VARINT_MAX_BYTE_LEN) {
            return NGX_AGAIN;
        }
        goto preread_failure;
    }

    if (buflast - bufpos < (ssize_t)ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (bufpos[0] != (u_char)'\0') {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        goto preread_failure;
    }
    ++bufpos;

    if (ctx->phase == HANDSHAKE_PHASE) {
        ctx->handshake_len = ctx->expected_packet_len;
        ctx->handshake_varint_byte_len = byte_len;

        protocol_num = read_minecraft_varint(bufpos, &byte_len);

        ctx->protocol_num = protocol_num;
        if (is_protocol_num_acceptable_by_ctx(ctx) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0, "Protocol number %d is not acceptable", protocol_num);
            goto preread_failure;
        }
        bufpos += byte_len;

        prefix_len = read_minecraft_varint(bufpos, &byte_len);
        if (prefix_len <= 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "There's a problem getting host string length (%d)", prefix_len);
            goto preread_failure;
        }
        bufpos += byte_len;

        if (ctx->remote_hostname == NULL) {
            hostname_str = parse_string_from_packet(ctx->pool, bufpos, prefix_len);
            if (hostname_str == NULL) {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot retrieve hostname");
                goto preread_failure;
            }

            ctx->remote_hostname = hostname_str;
            ctx->remote_hostname_len = prefix_len;
            bufpos += prefix_len;
        } else {
            hostname_str = ctx->remote_hostname;
            bufpos += ctx->remote_hostname_len;
        }

        ctx->remote_port |= (bufpos[0] << 8);
        ctx->remote_port |= bufpos[1];

        bufpos += PORT_LEN; /* Port */

        if (bufpos[0] == (u_char)'\1') {
            ctx->phase = STATUS_PHASE;
        } else if (bufpos[0] == (u_char)'\2') {
            ctx->phase = LOGIN_START_PHASE;
        } else {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Unknown next state (%d)", bufpos[0]);
            goto preread_failure;
        }
        ++bufpos;
    }

    if (ctx->phase == STATUS_PHASE) {
        goto end_of_preread;
    }

    c->log->action = "prereading minecraft loginstart packet";

    u_char *h_pos = c->buffer->pos + ctx->handshake_len + ctx->handshake_varint_byte_len;
    buflast = c->buffer->last;
    bufpos = h_pos;
    bufpos = parse_packet_length(s, bufpos, NULL);
    if (bufpos == NULL) {
        if (buflast - h_pos < VARINT_MAX_BYTE_LEN) {
            return NGX_AGAIN;
        }
        goto preread_failure;
    }

    if (buflast - bufpos < (ssize_t)ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (bufpos[0] != (u_char)'\0') {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        goto preread_failure;
    }
    ++bufpos;

    prefix_len = read_minecraft_varint(bufpos, &byte_len);
    if (prefix_len <= 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "There's a problem getting username string length (%d)", prefix_len);
        goto preread_failure;
    }
    if (prefix_len > 16) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Username too long (%d)", prefix_len);
        goto preread_failure;
    }
    bufpos += byte_len;

    username_str = parse_string_from_packet(ctx->pool, bufpos, prefix_len);
    if (username_str == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot retrieve username");
        goto preread_failure;
    }

    bufpos += prefix_len;

    if (ctx->protocol_num >= MINECRAFT_1_19_3) {
        if (ctx->protocol_num <= MINECRAFT_1_20_1) {
            ++bufpos;
        }

        uuid = ngx_pcalloc(ctx->pool, 33 * sizeof(u_char));
        if (uuid) {
            for (int i = 0; i < 32; ++i) {
                if (i % 2) {
                    uuid[i] = bufpos[i / 2] & (u_char)0x0F;
                } else {
                    uuid[i] = (bufpos[i / 2] & (u_char)0xF0) >> 4;
                }
                if (uuid[i] <= 9) {
                    uuid[i] += '0';
                } else if (uuid[i] >= 10 && uuid[i] <= 15) {
                    uuid[i] = 'a' + (uuid[i] - 10);
                } else {
                    goto preread_failure;
                }
            }
        }

        bufpos += 16;
    }

end_of_preread:
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Preread: Protocol num: %d, "
                  "Hostname provided: %s, "
                  "Username: %s, "
                  "UUID: %s, "
                  "Next state: %s",
                  ctx->protocol_num,
                  hostname_str ? hostname_str : (u_char *)"*Missing*",
                  username_str ? username_str : (u_char *)"*Missing*",
                  uuid ? uuid : (u_char *)"*Missing*",
                  ctx->phase == STATUS_PHASE ? "status" : "login");

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

ngx_str_t *get_new_hostname_str(ngx_stream_minecraft_forward_module_srv_conf_t *sconf, u_char *old_str, size_t old_str_len) {
    if (!sconf || old_str == NULL) {
        return NULL;
    }
    return (ngx_str_t *)ngx_hash_find(&sconf->hostname_map, ngx_hash_key(old_str, old_str_len), old_str, old_str_len);
}

static ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain, ngx_uint_t from_upstream) {
    ngx_connection_t *c = s->connection;
    ngx_int_t rc;
    if (c->type != SOCK_STREAM || chain == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    ngx_stream_minecraft_forward_ctx_t *ctx;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    ngx_str_t *new_hostname = NULL;
    u_char *new_hostname_str = NULL;
    u_char *new_hostname_varint_bytes = NULL;
    size_t new_hostname_varint_byte_len = 0;
    size_t new_hostname_str_len = 0;

    size_t protocol_varint_byte_len = 0;
    u_char *protocol_num_varint = NULL;

    size_t new_handshake_len = 0;
    size_t new_handshake_varint_byte_len = 0;
    u_char *new_handshake_varint_bytes = NULL;

    c->log->action = "filtering minecraft packet";
    if (ctx->pinged) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "Closing connection because already used for pinging");
        goto filter_failure;
    }

    ngx_stream_minecraft_forward_module_srv_conf_t *sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);

    if (from_upstream) {
        if (ctx->phase == STATUS_PHASE) {
            u_char *bufpos = parse_packet_length(s, c->buffer->pos, NULL);
            if (bufpos == NULL) {
                if (c->buffer->last - c->buffer->pos < VARINT_MAX_BYTE_LEN) {
                    return NGX_AGAIN;
                }
                return NGX_ERROR;
            }

            if (c->buffer->last - bufpos < (ssize_t)ctx->expected_packet_len) {
                return NGX_AGAIN;
            }

            if (!ctx->pinged) {
                ctx->pinged = 1;
            }
        }
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    if (!sconf->replace_on_ping && ctx->phase != LOGIN_START_PHASE) {
        return ngx_stream_next_filter(s, chain, from_upstream);
    }

    switch (ctx->phase) {
        case LOGIN_START_PHASE:
            c->log->action = "filtering and forwarding new minecraft login packet";
            break;
        case STATUS_PHASE:
            c->log->action = "filtering and forwarding minecraft ping packet";
            break;
        default:
            c->log->action = "filtering minecraft packet";
            goto filter_failure;
    }

    protocol_num_varint = create_minecraft_varint(ctx->pool, ctx->protocol_num, &protocol_varint_byte_len);
    if (protocol_num_varint == NULL) {
        goto filter_failure;
    }

    new_hostname = get_new_hostname_str(sconf, ctx->remote_hostname, ctx->remote_hostname_len);
    if (new_hostname == NULL) {
        if (sconf->disconnect_on_nomatch) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "Closing connection because no hostname match");
            goto filter_failure;
        }
        new_hostname_str = ctx->remote_hostname;
        new_hostname_str_len = ctx->remote_hostname_len;
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
    new_handshake_len = 1 + protocol_varint_byte_len + new_hostname_varint_byte_len + new_hostname_str_len + PORT_LEN + 1;

    // The whole packet is prefixed by a total length in varint.
    new_handshake_varint_bytes = create_minecraft_varint(ctx->pool, new_handshake_len, &new_handshake_varint_byte_len);
    if (new_handshake_varint_bytes == NULL) {
        goto filter_failure;
    }

    size_t old_handshake_len = ctx->handshake_varint_byte_len + ctx->handshake_len;
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "old_handshake_len: %d", old_handshake_len);
    new_handshake_len = new_handshake_varint_byte_len + new_handshake_len;

    ngx_chain_t *target_chain_node = NULL;
    size_t in_buf_len;
    ngx_int_t last = 0;
    size_t gathered_len = 0;

    for (ngx_chain_t *ln = chain; ln != NULL; ln = ln->next) {
        in_buf_len = ngx_buf_size(ln->buf);
        if (in_buf_len <= 0) {
            goto filter_failure;
        }
        gathered_len += in_buf_len;
        if (ln->buf->last_buf) {
            last = 1;
        }
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "gathered_len: %d", gathered_len);
        if (gathered_len >= old_handshake_len) {
            target_chain_node = ln;
            break;
        }
    }
    if (last) {
        if (gathered_len < old_handshake_len) {
            goto filter_failure;
        }
    }

    size_t split_remnant_len = gathered_len - old_handshake_len;

    ngx_chain_t *new_chain = ngx_chain_get_free_buf(c->pool, &ctx->filter_free);
    if (new_chain == NULL) {
        goto filter_failure;
    }
    new_chain->buf->pos = ngx_pcalloc(c->pool, new_handshake_len * sizeof(u_char));
    if (new_chain->buf->pos == NULL) {
        goto filter_failure;
    }
    new_chain->buf->start = new_chain->buf->pos;
    new_chain->buf->last = new_chain->buf->pos;
    new_chain->buf->end = new_chain->buf->start + (new_handshake_len * sizeof(u_char));
    new_chain->buf->tag = (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module;
    new_chain->buf->memory = 1;

    new_chain->buf->last = ngx_cpymem(new_chain->buf->pos, new_handshake_varint_bytes, new_handshake_varint_byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, (u_char *)"\0", 1); // Packet id 0x00
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, protocol_num_varint, protocol_varint_byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_varint_bytes, new_hostname_varint_byte_len);
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, new_hostname_str, new_hostname_str_len);
    u_char p = (ctx->remote_port & 0xFF00) >> 8;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &p, 1);
    p = ctx->remote_port & 0x00FF;
    new_chain->buf->last = ngx_cpymem(new_chain->buf->last, &p, 1);
    switch (ctx->phase) {
        case LOGIN_START_PHASE:
            new_chain->buf->last = ngx_cpymem(new_chain->buf->last, (u_char *)"\2", 1); // Next state
            break;
        case STATUS_PHASE:
            new_chain->buf->last = ngx_cpymem(new_chain->buf->last, (u_char *)"\1", 1);
            break;
        default:
            goto filter_failure;
    }
    ngx_log_debug6(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "new_handshake_len: %d, "
                   "new_handshake_varint_byte_len: %d, "
                   "ctx protocol_num: %d, "
                   "protocol_varint_byte_len: %d, "
                   "new_hostname_varint_byte_len: %d, "
                   "new_hostname_str_len: %d",
                   new_handshake_len,
                   new_handshake_varint_byte_len,
                   ctx->protocol_num,
                   protocol_varint_byte_len,
                   new_hostname_varint_byte_len,
                   new_hostname_str_len);

    ngx_chain_t *split_remnant_chain = NULL;
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "split_remnant_len: %d", split_remnant_len);
    if (split_remnant_len > 0) {
        split_remnant_chain = ngx_chain_get_free_buf(c->pool, &ctx->filter_free);
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

        split_remnant_chain->buf->last = ngx_cpymem(split_remnant_chain->buf->pos, target_chain_node->buf->last - split_remnant_len, split_remnant_len);
    }
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "Filter: Provided hostname: %s, "
                  "New hostname string: %s",
                  ctx->remote_hostname,
                  new_hostname_str);


    // https://nginx.org/en/docs/dev/development_guide.html#http_body_buffers_reuse

    ngx_chain_t *chain_out, **link_i, *append_i;

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

    rc = ngx_stream_next_filter(s, chain_out, from_upstream);
    ngx_chain_update_chains(c->pool, &ctx->filter_free, &ctx->filter_busy, &chain_out, (ngx_buf_tag_t)&ngx_stream_minecraft_forward_module);

    if (ctx->phase == STATUS_PHASE) {
        if (sconf->replace_on_ping) {
            switch (rc) {
                case NGX_OK:
                    goto end_of_filter;
                case NGX_AGAIN:
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
    ngx_stream_handler_pt *hp;
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
