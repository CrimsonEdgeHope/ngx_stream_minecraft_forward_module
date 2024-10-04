#ifndef _NSMFM_STREAM_SESSION_CONTEXT_
#define _NSMFM_STREAM_SESSION_CONTEXT_

#include <ngx_core.h>
#include "nsmfm_handler.h"
#include "../protocol/nsmfm_packet.h"
#include <stdbool.h>

typedef struct {
    nsmfm_preread_handler  handler;
    bool                   pass;
    bool                   fail;

    minecraft_packet      *handshake;
    minecraft_packet      *loginstart;

    u_char                *bufpos;

    ngx_pool_t            *pool;
} nsmfm_session_context;

#define _NSMFM_SESSION_CTX_DEFAULT_POOL_SIZE_ 2048

bool nsmfm_create_session_context(ngx_stream_session_t *s);
nsmfm_session_context *nsmfm_get_session_context(ngx_stream_session_t *s);
void nsmfm_remove_session_context(ngx_stream_session_t *s);

#endif
