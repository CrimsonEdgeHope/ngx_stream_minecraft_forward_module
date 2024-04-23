#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include <ngx_string.h>

typedef struct {
    ngx_hash_t             hostname_map;
    ngx_hash_init_t        hostname_map_init;
    ngx_hash_keys_arrays_t hostname_map_keys; /* Both `key` and `value` are `ngx_str_t *` */
    size_t                 hash_max_size;
    size_t                 hash_bucket_size;

    ngx_flag_t             replace_on_ping;
    ngx_flag_t             disconnect_on_nomatch;
    ngx_flag_t             enabled;
} ngx_stream_minecraft_forward_module_srv_conf_t;

typedef ngx_int_t (*ngx_stream_minecraft_forward_module_preread_handler_pt)(ngx_stream_session_t *s);

typedef struct {
    ngx_stream_minecraft_forward_module_preread_handler_pt  preread_handler;

    u_short       state : 2;

    u_short       preread_pass : 1;
    u_short       pinged : 1;
    u_short       fail : 1;

    ngx_pool_t   *pool;

    ngx_int_t     protocol_num;
    ngx_str_t     protocol_num_varint;

    ngx_str_t     provided_hostname;
    size_t        provided_hostname_varint_byte_len;

    u_short       remote_port;

    ngx_str_t     username;
    size_t        username_varint_byte_len;
    ngx_str_t     uuid;

    size_t        handshake_varint_byte_len;   /* The varint itself, 5 at most. */
    size_t        handshake_len;               /* The handshake packet's length, derived from the preceding varint. */

    size_t        loginstart_varint_byte_len;
    size_t        loginstart_len;              /* The loginstart packet's length. */

    size_t        expected_packet_len;         /* Derived from the preceding varint. */

#if (nginx_version >= 1025005)
    ngx_chain_t  *in;
#endif

    // https://nginx.org/en/docs/dev/development_guide.html#http_body_buffers_reuse

    ngx_chain_t  *out;
    ngx_chain_t  *free_chain;
    ngx_chain_t  *busy_chain;
} ngx_stream_minecraft_forward_ctx_t;

extern ngx_module_t ngx_stream_minecraft_forward_module;

#if (NGX_PCRE)
extern ngx_regex_t *ngx_stream_minecraft_forward_module_srv_hostname_check_regex;
#endif

#endif
