#include <ngx_core.h>
#include <ngx_stream.h>
#include "../main/ngx_stream_minecraft_forward_module.h"
#include "nsmfpm_session.h"
#include "../protocol/nsmfm_packet.h"
#include "../protocol/nsmfm_protocol_number.h"
#include "../utils/nsmfm_varint.h"
#include "../utils/nsmfm_packet.h"
#include "../utils/nsmfm_hostname.h"
#include "../filter/nsmfcfm_session.h"

static ngx_int_t nsmfpm_post_init(ngx_conf_t *cf);

static ngx_int_t nsmfpm(ngx_stream_session_t *s);
static ngx_int_t nsmfpm_handshake(ngx_stream_session_t *s);
static ngx_int_t nsmfpm_loginstart(ngx_stream_session_t *s);

static ngx_stream_module_t nsmfpm_conf_ctx = {
    NULL,  /* preconfiguration */
    nsmfpm_post_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL  /* merge server configuration */
};

ngx_module_t ngx_stream_minecraft_forward_preread_module = {
    NGX_MODULE_V1,
    &nsmfpm_conf_ctx,      /* module conf context */
    NULL,                  /* module directives */
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

static ngx_int_t nsmfpm(ngx_stream_session_t *s) {
    ngx_connection_t        *c;
    nsmfm_srv_conf_t        *sconf;
    nsmfpm_session_context  *ctx;

    ngx_int_t                rc;

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

    ctx = nsmfpm_get_session_context(s);
    if (ctx == NULL) {
        if (!nsmfpm_create_session_context(s)) {
            return NGX_ERROR;
        }
        ctx = nsmfpm_get_session_context(s);
        ctx->handler = nsmfpm_handshake;
    }

    if (ctx->pass) {
        rc = NGX_OK;
        goto end_of_preread;
    }

    rc = ctx->handler(s);

    if (rc == NGX_ERROR) {
        goto preread_failure;
    }

end_of_preread:
    if (ctx->fail) {
        nsmfpm_remove_session_context(s);
        nsmfcfm_remove_session_context(s);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Preread failed");
        rc = NGX_ERROR;
    }

    return rc;

preread_failure:
    ctx->fail = 1;
    goto end_of_preread;
}

static ngx_int_t nsmfpm_handshake(ngx_stream_session_t *s) {
    ngx_connection_t         *c;
    nsmfpm_session_context   *ctx;
    nsmfcfm_session_context  *cfctx;

    u_char                   *bufpos;
    ngx_int_t                 var;
    u_char                    p;

    ngx_flag_t                buffer_remanent;
    int                       byte_len;

    minecraft_handshake      *handshake;

    c = s->connection;
    c->log->action = "prereading minecraft handshake packet";

    ctx = nsmfpm_get_session_context(s);

    if (!ctx->handshake) {
        ctx->handshake = ngx_pcalloc(ctx->pool, sizeof(minecraft_packet));
        if (!ctx->handshake) {
            return NGX_ERROR;
        }
    }

    bufpos = c->buffer->pos;

    if (ctx->handshake->length.num <= 0) {
        var = nsmfm_get_packet_length(ctx->handshake, &bufpos, c->buffer->last, &byte_len);
        if (var != NGX_OK) {
            return var;
        }
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, handshake content len: %d", ctx->handshake->length.num);
        ctx->bufpos = bufpos;
    }

    if (!ctx->handshake->content) {
        bufpos = ctx->bufpos;
        var = nsmfm_receive_packet(ctx->handshake, bufpos, c->buffer->last, nsmfm_handshake_packet_init, ctx->pool);
        if (var != NGX_OK) {
            return var;
        }
        if (bufpos[0] != ctx->handshake->id.bytes[0]) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "Read unexpected packet id (%d), (%d) is expected",
                          bufpos[0], ctx->handshake->id.bytes[0]);
            return NGX_ERROR;
        }
        bufpos++;
        ctx->bufpos = bufpos;
    }

    handshake = ctx->handshake->content;

    bufpos = ctx->bufpos;

    if (!nsmfm_parse_varint_fill_object(bufpos, &handshake->protocol_number)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read protocol number");
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read varint, protocol number: %d", handshake->protocol_number.num);
    if (!nsmfm_is_known_protocol(handshake->protocol_number)) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Unknown protocol number: %d", handshake->protocol_number.num);
        return NGX_ERROR;
    }

    bufpos += handshake->protocol_number.byte_len;

    var = nsmfm_get_string(&bufpos, &handshake->server_address, ctx->pool);
    if (var != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read server hostname");
        return var;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read hostname: %s", handshake->server_address.content);

    handshake->server_port |= (bufpos[0] << 8);
    handshake->server_port |= bufpos[1];
    bufpos += _MC_PORT_LEN_;
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read remote port: %d", handshake->server_port);

    nsmfm_fill_varint_object(bufpos[0], &handshake->next_state);
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
            ctx->handler = nsmfpm_loginstart;
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

static ngx_int_t nsmfpm_loginstart(ngx_stream_session_t *s) {
    ngx_connection_t         *c;
    nsmfpm_session_context   *ctx;
    nsmfcfm_session_context  *cfctx;

    u_char                   *bufpos;
    ngx_int_t                 var;
    int                       byte_len;
    u_char                   *uuid;

    minecraft_handshake      *handshake;
    minecraft_loginstart     *loginstart;

    c = s->connection;
    c->log->action = "prereading minecraft loginstart packet";

    ctx = nsmfpm_get_session_context(s);
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
        var = nsmfm_get_packet_length(ctx->loginstart, &bufpos, c->buffer->last, &byte_len);
        if (var != NGX_OK) {
            return var;
        }
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                      "read varint, loginstart content len: %d", ctx->loginstart->length.num);
        ctx->bufpos = bufpos;
    }

    if (!ctx->loginstart->content) {
        bufpos = ctx->bufpos;
        var = nsmfm_receive_packet(ctx->loginstart, bufpos, c->buffer->last, nsmfm_loginstart_packet_init , ctx->pool);
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

    var = nsmfm_get_string(&bufpos, &loginstart->username, ctx->pool);
    if (var != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "Cannot read username");
        return var;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "read username: %s", loginstart->username.content);

    if (handshake->protocol_number.num >= MINECRAFT_1_19_3) {
        uuid = loginstart->uuid;
        if (handshake->protocol_number.num <= MINECRAFT_1_20_1) {
            bufpos++;
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

static ngx_int_t nsmfpm_post_init(ngx_conf_t *cf) {
    ngx_stream_handler_pt       *hp;
    ngx_stream_core_main_conf_t *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    hp = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (hp == NULL) {
        return NGX_ERROR;
    }
    *hp = nsmfpm;

    return NGX_OK;
}
