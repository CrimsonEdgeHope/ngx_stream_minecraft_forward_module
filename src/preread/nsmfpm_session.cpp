extern "C"
{
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_stream_minecraft_forward_preread_module.h"
}
#include "nsmfpm_session.hpp"

bool nsmfpm_create_session_context(ngx_stream_session_t *s) {
    nsmfpm_session_context  *ctx;

    ctx = nsmfpm_get_session_context(s);
    if (ctx == NULL) {
        ctx = (nsmfpm_session_context *) ngx_pcalloc(s->connection->pool, sizeof(nsmfpm_session_context));
        if (ctx == NULL) {
            return false;
        }

        ctx->pool = ngx_create_pool(_NSMFPM_SESSION_CTX_DEFAULT_POOL_SIZE_, s->connection->log);
        if (ctx->pool == NULL) {
            return false;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_minecraft_forward_preread_module);
    }

    return true;
}

nsmfpm_session_context *nsmfpm_get_session_context(ngx_stream_session_t *s) {
    return (nsmfpm_session_context *) ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_preread_module);
}

void nsmfpm_remove_session_context(ngx_stream_session_t *s) {
    nsmfpm_session_context *ctx;

    ctx = nsmfpm_get_session_context(s);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "ngx_stream_minecraft_forward_preread_module: Removing session context");
#endif

    if (ctx->handshake) {
        delete ctx->handshake;
        ctx->handshake = nullptr;
    }
    if (ctx->loginstart) {
        delete ctx->loginstart;
        ctx->loginstart = nullptr;
    }

    if (ctx) {
        if (ctx->pool) {
            ngx_destroy_pool(ctx->pool);
            ctx->pool = NULL;
        }
        ngx_pfree(s->connection->pool, ctx);
    }

    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_preread_module);
}
