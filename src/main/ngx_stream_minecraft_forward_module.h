#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_

#include <ngx_core.h>

typedef struct {
    ngx_hash_t             hostname_map;
    ngx_hash_init_t        hostname_map_init;
    ngx_hash_keys_arrays_t hostname_map_keys; /* Both `key` and `value` are `ngx_str_t *` */
    size_t                 hash_max_size;
    size_t                 hash_bucket_size;

    ngx_flag_t             replace_on_ping;
    ngx_flag_t             disconnect_on_nomatch;
    ngx_flag_t             enabled;
} nsmfm_srv_conf_t;

extern ngx_module_t ngx_stream_minecraft_forward_module;

#if (NGX_PCRE)
extern ngx_regex_t *nsmfm_validate_hostname_regex;
#endif

#endif
