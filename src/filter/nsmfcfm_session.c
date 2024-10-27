#include <ngx_core.h>
#include <ngx_stream.h>
#include <stdbool.h>
#include "nsmfcfm_session.h"
#include "ngx_stream_minecraft_forward_content_filter_module.h"

bool nsmfcfm_create_session_context(ngx_stream_session_t *s) {
    nsmfcfm_session_context  *ctx;

    ctx = nsmfcfm_get_session_context(s);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(nsmfcfm_session_context));
        if (ctx == NULL) {
            return false;
        }
        ctx->pool = ngx_create_pool(_NSMFCFM_SESSION_CTX_DEFAULT_POOL_SIZE_, s->connection->log);
        if (ctx->pool == NULL) {
            return false;
        }
        ngx_stream_set_ctx(s, ctx, ngx_stream_minecraft_forward_content_filter_module);
    }

    return true;
}

nsmfcfm_session_context *nsmfcfm_get_session_context(ngx_stream_session_t *s) {
    return ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_content_filter_module);
}

void nsmfcfm_remove_session_context(ngx_stream_session_t *s) {
    nsmfcfm_session_context  *ctx;

    ctx = nsmfcfm_get_session_context(s);

#if (NGX_DEBUG)
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "ngx_stream_minecraft_forward_content_filter_module: Removing session context");
#endif

    if (ctx) {
        if (ctx->pool) {
            ngx_destroy_pool(ctx->pool);
            ctx->pool = NULL;
        }
        ngx_pfree(s->connection->pool, ctx);
    }

    ngx_stream_set_ctx(s, NULL, ngx_stream_minecraft_forward_content_filter_module);
}
