#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include <ngx_string.h>

#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H

typedef struct {
    ngx_hash_t domain_map;
    ngx_hash_init_t domain_map_init;
    /* Both `key` and `value` are `ngx_str_t *` */
    ngx_hash_keys_arrays_t domain_map_keys;
    size_t hash_max_size;
    size_t hash_bucket_size;
    ngx_flag_t replace_on_ping;

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

    ngx_chain_t *filter_free;
    ngx_chain_t *filter_busy;
} ngx_stream_minecraft_forward_module_ctx_t;

extern ngx_module_t ngx_stream_minecraft_forward_module;

#if (NGX_PCRE)
extern ngx_regex_t *ngx_stream_minecraft_forward_module_srv_domain_check_regex;
#endif

#endif
