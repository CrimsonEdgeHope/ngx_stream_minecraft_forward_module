#ifndef _NSMFPM_STREAM_SESSION_CONTEXT_
#define _NSMFPM_STREAM_SESSION_CONTEXT_

#include <ngx_core.h>
#include <ngx_stream.h>
#include "../protocol/nsmfm_packet.h"
#include <stdbool.h>

typedef ngx_int_t (*nsmfm_preread_handler)(ngx_stream_session_t *s);

typedef struct {
    nsmfm_preread_handler  handler;
    bool                   pass;
    bool                   fail;

    minecraft_packet      *handshake;
    minecraft_packet      *loginstart;

    u_char                *bufpos;

    ngx_pool_t            *pool;
} nsmfpm_session_context;

#define _NSMFPM_SESSION_CTX_DEFAULT_POOL_SIZE_ 2048

bool nsmfpm_create_session_context(ngx_stream_session_t *s);
nsmfpm_session_context *nsmfpm_get_session_context(ngx_stream_session_t *s);
void nsmfpm_remove_session_context(ngx_stream_session_t *s);

#endif
