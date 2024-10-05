#ifndef _NSMFCFM_STREAM_SESSION_CONTEXT_
#define _NSMFCFM_STREAM_SESSION_CONTEXT_

#include <ngx_core.h>
#include <ngx_stream.h>
#include <stdbool.h>

#define _NSMFCFM_SESSION_CTX_DEFAULT_POOL_SIZE_ 2048

typedef struct {
    bool          pinged;
    bool          fail;

    ngx_chain_t  *in;
    ngx_chain_t  *out;
    ngx_chain_t  *free_chain;
    ngx_chain_t  *busy_chain;

    ngx_pool_t   *pool;
} nsmfcfm_session_context;

bool nsmfcfm_create_session_context(ngx_stream_session_t *s);
nsmfcfm_session_context *nsmfcfm_get_session_context(ngx_stream_session_t *s);
void nsmfcfm_remove_session_context(ngx_stream_session_t *s);

#endif
