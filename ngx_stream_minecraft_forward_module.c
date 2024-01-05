#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

typedef struct {
    ngx_flag_t enabled;
} ngx_stream_minecraft_forward_module_srv_conf_t;

typedef struct {
    u_short phase; /* 0: Handshake, 1: Status, 2: Login start */
    ngx_int_t protocol_num;

    u_int expected_packet_len;
    u_char *pos;
} ngx_stream_minecraft_forward_module_ctx_t;

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *curr);

static ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s);

static ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf);

static ngx_command_t ngx_stream_minecraft_forward_module_directives[] = {
    {ngx_string("minecraft_server_forward"), /* Indicate a server block that proxies minecraft tcp connections. */
     NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_minecraft_forward_module_srv_conf_t, enabled),
     NULL},
    ngx_null_command /* END */
};

ngx_stream_module_t ngx_stream_minecraft_forward_module_conf_ctx = {
    NULL,                                          /* preconfiguration */
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
    NGX_MODULE_V1_PADDING                           /* No padding*/
};

static void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf) {
    ngx_stream_minecraft_forward_module_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_minecraft_forward_module_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enabled = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *curr) {
    ngx_stream_minecraft_forward_module_srv_conf_t *parent = prev;
    ngx_stream_minecraft_forward_module_srv_conf_t *current = curr;

    ngx_conf_merge_value(current->enabled, parent->enabled, 0);

    return NGX_CONF_OK;
}

ngx_int_t read_minecraft_varint(u_char *buf, u_int *byte_len) {
    ngx_int_t value = 0;
    ngx_int_t bit_pos = 0;
    u_char *byte = buf;
    while (1) {
        value |= (*byte & 0x7F) << bit_pos;
        if ((*byte & 0x80) == 0) {
            break;
        }

        bit_pos += 7;

        if (bit_pos >= 32) {
            return -1;
        }

        ++byte;
    }
    *byte_len = byte - buf + 1;
    return value;
}

u_char *parse_packet_length(ngx_stream_session_t *s, ngx_stream_minecraft_forward_module_ctx_t *ctx, u_char *bufpos, u_int *varint_byte_len, ngx_int_t *packet_len) {
    if (ctx->expected_packet_len == 0) {
        *packet_len = read_minecraft_varint(bufpos, varint_byte_len);
        if (*packet_len <= 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "Cannot decode varint properly(%d). At this moment, a correct packet with content is expected", *packet_len);
            return NULL;
        }
        ctx->expected_packet_len = *packet_len;

        bufpos += *varint_byte_len;
        ctx->pos = bufpos;
    }

    return bufpos;
}

u_char *parse_string_from_packet(ngx_pool_t *pool, u_char *bufpos, ngx_int_t len) {
    u_char *rs;
    rs = ngx_pcalloc(pool, (len + 1) * sizeof(u_char));
    if (rs == NULL) {
        return NULL;
    }
    ngx_memcpy(rs, bufpos, len);
    rs[len] = '\0';
    return rs;
}

/* UNTESTED */
void create_minecraft_varint(u_char *result, ngx_int_t value) {
    if (result == NULL) {
        return;
    }

    ngx_int_t v = value;
    u_int i = 0;
    u_int msb = 0;
    u_int count = 0;

    while (v > 0) {
        i = v & 0x7F;
        msb = i & 0x40;
        msb <<= 1;
        i |= msb;
        result[count] = (u_char)i;
        v >>= 7;
    }
}

/* UNTESTED */
u_char *ngx_create_minecraft_varint(ngx_pool_t *pool, ngx_int_t value) {
    if (pool == NULL || value < 0) {
        return NULL;
    }

    u_char *varint = ngx_pcalloc(pool, sizeof(u_char) * 5);
    create_minecraft_varint(varint, value);
    return varint;
}

void destory_preread_ctx(ngx_stream_session_t *s) {
    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_module);
}

ngx_int_t echo_deny_connection(ngx_stream_session_t *s) {
    destory_preread_ctx(s);
    return NGX_ERROR;
}

/* Assertion of all protocols referring to Minecraft Java since Netty rewrite */
ngx_int_t is_protocol_num_acceptable(ngx_stream_minecraft_forward_module_ctx_t *ctx) {
    switch (ctx->protocol_num) {
        case 765: // 1.20.3  1.20.4
        case 764: // 1.20.2
        case 763: // 1.20    1.20.1
        case 762: // 1.19.4
        case 761: // 1.19.3
        case 760: // 1.19.1  1.19.2
        case 759: // 1.19
            return NGX_OK;
        default:
            return NGX_ERROR;
    }
}

static ngx_int_t ngx_stream_minecraft_forward_module_handshake_preread(ngx_stream_session_t *s) {
    ngx_connection_t *c = s->connection;
    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    ngx_stream_minecraft_forward_module_srv_conf_t *sconf = ngx_stream_get_module_srv_conf(s, ngx_stream_minecraft_forward_module);
    if (!sconf->enabled) {
        return NGX_DECLINED;
    }
    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ngx_stream_minecraft_forward_module_ctx_t *ctx;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_minecraft_forward_module));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->phase = 0;
        ctx->pos = c->buffer->pos;
        ngx_stream_set_ctx(s, ctx, ngx_stream_minecraft_forward_module);
    }

    if (ctx->phase != 0) {
        return NGX_OK;
    }

    u_char *bufpos = ctx->pos;
    u_char *buflast = c->buffer->last;

    if (buflast - bufpos < 5) {
        return NGX_AGAIN;
    }

    if (ctx->phase == 0 && bufpos[0] == (u_char)'\xFE') { // Legacy ping 0xFE
        return echo_deny_connection(s);
    }

    u_int byte_len = 0;
    ngx_int_t prefix_len = 0;
    bufpos = parse_packet_length(s, ctx, bufpos, &byte_len, &prefix_len);
    if (bufpos == NULL) {
        return echo_deny_connection(s);
    }

    if (buflast - bufpos < ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (bufpos[0] != (u_char)'\0') {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        return echo_deny_connection(s);
    }
    ++bufpos;

    if (ctx->phase == 0) {
        ngx_int_t protocol_num = -1;
        protocol_num = read_minecraft_varint(bufpos, &byte_len);
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "Protocol number: %d", protocol_num);
        ctx->protocol_num = protocol_num;
        if (is_protocol_num_acceptable(ctx) != NGX_OK) {
            return echo_deny_connection(s);
        }
        bufpos += byte_len;

        prefix_len = read_minecraft_varint(bufpos, &byte_len);
        if (prefix_len <= 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "There's a problem getting host string length (%d)", prefix_len);
            return echo_deny_connection(s);
        }
        bufpos += byte_len;

        /* Change this later */
        u_char *host_str = parse_string_from_packet(c->pool, bufpos, prefix_len);
        if (host_str == NULL) {
            return echo_deny_connection(s);
        }
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "Remote hostname: %s", host_str);
        ngx_pfree(c->pool, host_str);
        host_str = NULL;
        /* Change this later */
        bufpos += prefix_len;

        bufpos += sizeof(u_short); /* Port */

        if (bufpos[0] == (u_char)'\1') {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "Next state: Status");
            ctx->phase = 1;
        } else if (bufpos[0] == (u_char)'\2') {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "Next state: Login");
            ctx->phase = 2;
        } else {
            ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Unknown next state (%d)", bufpos[0]);
            return echo_deny_connection(s);
        }
        ++bufpos;
    } else {
        ngx_log_error(NGX_LOG_CRIT, c->log, 0, "Unknown or wrong phase case (%d) in handshake preread handler", ctx->phase);
        return echo_deny_connection(s);
    }

    ctx->pos = bufpos;
    ctx->expected_packet_len = 0;
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "End of handshake preread");
    return ngx_stream_minecraft_forward_module_loginstart_preread(s);
}

static ngx_int_t ngx_stream_minecraft_forward_module_loginstart_preread(ngx_stream_session_t *s) {
    ngx_connection_t *c = s->connection;

    ngx_stream_minecraft_forward_module_ctx_t *ctx;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_CRIT, c->log, 0, "Contextual data missing in loginstart preread handler! This should not happen");
        return echo_deny_connection(s);
    }
    if (ctx->phase != 2) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "Wrong phase (%d) in loginstart preread handler", ctx->phase);
        return echo_deny_connection(s);
    }

    u_char *bufpos = ctx->pos;
    u_char *buflast = c->buffer->last;

    if (buflast - bufpos < 5) {
        return NGX_AGAIN;
    }

    u_int byte_len = 0;
    ngx_int_t prefix_len = 0;
    bufpos = parse_packet_length(s, ctx, bufpos, &byte_len, &prefix_len);
    if (bufpos == NULL) {
        return echo_deny_connection(s);
    }

    if (buflast - bufpos < ctx->expected_packet_len) {
        return NGX_AGAIN;
    }

    if (bufpos[0] != (u_char)'\0') {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Unexpected packet id (%d), 0x00 is expected", bufpos[0]);
        return echo_deny_connection(s);
    }
    ++bufpos;

    prefix_len = read_minecraft_varint(bufpos, &byte_len);
    if (prefix_len <= 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "There's a problem getting username string length (%d)", prefix_len);
        return echo_deny_connection(s);
    }
    if (prefix_len > 16) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Username too long (%d)", prefix_len);
        return echo_deny_connection(s);
    }
    bufpos += byte_len;

    /* Change this later */
    u_char *username_str = parse_string_from_packet(c->pool, bufpos, prefix_len);
    if (username_str == NULL) {
        return echo_deny_connection(s);
    }
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "Username: %s", username_str);
    ngx_pfree(c->pool, username_str);
    username_str = NULL;
    /* Change this later */
    bufpos += prefix_len;

    /* END */
    ctx->phase = 0;
    ctx->expected_packet_len = 0;
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "End of loginstart preread");
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
    *hp = ngx_stream_minecraft_forward_module_handshake_preread;

    return NGX_OK;
}
