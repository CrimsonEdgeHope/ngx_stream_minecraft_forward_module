#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash.h>
#include <ngx_stream.h>

#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H

typedef struct {
    ngx_hash_t domain_map;
    ngx_hash_init_t domain_map_init;
    ngx_hash_keys_arrays_t domain_map_keys;

    size_t hash_max_size;
    size_t hash_bucket_size;

    ngx_flag_t enabled;
} ngx_stream_minecraft_forward_module_srv_conf_t;

typedef struct {
    u_short phase;
    u_short pass : 1;
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

void *ngx_stream_minecraft_forward_module_create_srv_conf(ngx_conf_t *cf);
char *ngx_stream_minecraft_forward_module_merge_srv_conf(ngx_conf_t *cf, void *prev, void *conf);

char *ngx_stream_minecraft_forward_module_srv_conf_minecraft_server_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_stream_minecraft_forward_module_preread(ngx_stream_session_t *s);

ngx_int_t ngx_stream_minecraft_forward_module_content_filter(ngx_stream_session_t *s, ngx_chain_t *chain, ngx_uint_t from_upstream);

ngx_int_t ngx_stream_minecraft_forward_module_post_init(ngx_conf_t *cf);

extern ngx_module_t ngx_stream_minecraft_forward_module;

#endif
