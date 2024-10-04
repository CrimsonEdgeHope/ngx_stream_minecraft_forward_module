#ifndef _NSMFM_MODULE_HANDLER_
#define _NSMFM_MODULE_HANDLER_

#include <ngx_core.h>
#include <ngx_stream.h>

typedef ngx_int_t (*nsmfm_preread_handler)(ngx_stream_session_t *s);

#endif
