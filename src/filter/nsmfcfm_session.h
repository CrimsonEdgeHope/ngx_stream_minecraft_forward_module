#ifndef _NSMFCFM_STREAM_SESSION_CONTEXT_
#define _NSMFCFM_STREAM_SESSION_CONTEXT_

#include <ngx_core.h>
#include <ngx_stream.h>
#include <stdbool.h>

typedef struct {
    bool          pinged;
    bool          fail;

    ngx_chain_t  *in;
    ngx_chain_t  *out;
    ngx_chain_t  *free_chain;
    ngx_chain_t  *busy_chain;
} nsmfcfm_session_context;

bool nsmfcfm_create_session_context(ngx_stream_session_t *s);
nsmfcfm_session_context *nsmfcfm_get_session_context(ngx_stream_session_t *s);
void nsmfcfm_remove_session_context(ngx_stream_session_t *s);

#endif
