#ifndef _NSMFM_STREAM_SESSION_CONTEXT_
#define _NSMFM_STREAM_SESSION_CONTEXT_

#include <ngx_core.h>
#include "./handler.h"
#include "../protocol/packet.h"
#include <stdbool.h>

typedef struct {
    nsmfm_preread_handler  preread_handler;
    bool                   preread_pass;

    bool                   pinged;
    bool                   fail;

    minecraft_packet      *handshake;
    minecraft_packet      *loginstart;
    ngx_int_t              state:3;

    u_char                *bufpos;
    int                    var1;
    int                    var2;

    ngx_pool_t            *pool;
    ngx_chain_t           *in;
    ngx_chain_t           *out;
    ngx_chain_t           *free_chain;
    ngx_chain_t           *busy_chain;
} nsmfm_session_context;

#endif
