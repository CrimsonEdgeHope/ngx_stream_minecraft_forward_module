#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include <ngx_string.h>

#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_

typedef struct {
    ngx_hash_t hostname_map;
    ngx_hash_init_t hostname_map_init;
    ngx_hash_keys_arrays_t hostname_map_keys; /* Both `key` and `value` are `ngx_str_t *` */
    size_t hash_max_size;
    size_t hash_bucket_size;

    ngx_flag_t replace_on_ping;
    ngx_flag_t disconnect_on_nomatch;
    ngx_flag_t enabled;
} ngx_stream_minecraft_forward_module_srv_conf_t;

typedef struct {
    u_short phase;
    u_short preread_pass : 1;
    u_short pinged : 1;

    ngx_int_t protocol_num; /* Minecraft Java protocol version number since Netty rewrite. */
    u_char *remote_hostname;
    size_t remote_hostname_len; /* String has preceding varint that indicates string length. */
    u_short remote_port;

    size_t handshake_varint_byte_len; /* The varint itself, 5 at most. */
    size_t handshake_len;             /* The handshake packet's length, derived from the preceding varint. */

    size_t expected_packet_len; /* Derived from the preceding varint. */

    u_short fail : 1;

    ngx_pool_t *pool;

    ngx_chain_t *filter_free;
    ngx_chain_t *filter_busy;
} ngx_stream_minecraft_forward_ctx_t;

extern ngx_module_t ngx_stream_minecraft_forward_module;

#if (NGX_PCRE)
extern ngx_regex_t *ngx_stream_minecraft_forward_module_srv_hostname_check_regex;
#endif

#endif
