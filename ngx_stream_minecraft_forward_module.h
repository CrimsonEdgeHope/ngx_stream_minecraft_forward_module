#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_

#include <ngx_core.h>
#include "./module/handler.h"
#include "./module/session.h"

extern ngx_module_t ngx_stream_minecraft_forward_module;

#if (NGX_PCRE)
extern ngx_regex_t *nsmfm_validate_hostname_regex;
#endif

#endif
