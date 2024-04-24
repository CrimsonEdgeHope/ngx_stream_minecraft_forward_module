#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash.h>
#include <ngx_stream.h>
#include <ngx_string.h>

typedef ngx_int_t (*ngx_stream_minecraft_preread_handler)(ngx_stream_session_t *s);

typedef struct {
    ngx_str_t  varint;
} ngx_stream_minecraft_varint_t;

typedef struct {
    ngx_str_t                      content;
    ngx_stream_minecraft_varint_t  varint_of_length;
} ngx_stream_minecraft_packet_t;

typedef struct {
    ngx_stream_minecraft_varint_t  original;
    ngx_int_t                      number;
} ngx_stream_minecraft_protocol_number_t;

typedef struct {
    ngx_str_t                      text;
    ngx_stream_minecraft_varint_t  varint_of_length;
} ngx_stream_minecraft_str_t;

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

typedef struct {
    ngx_stream_minecraft_preread_handler     preread_handler;

    ngx_int_t                                preread_pass : 1;
    ngx_int_t                                pinged : 1;
    ngx_int_t                                fail : 1;

    ngx_pool_t                              *pool;

    u_short                                  state : 2;

    ngx_stream_minecraft_protocol_number_t   protocol;
    ngx_stream_minecraft_str_t               provided_hostname;
    u_short                                  remote_port;
    ngx_stream_minecraft_str_t               username;
    ngx_stream_minecraft_str_t               uuid_byte;
    ngx_str_t                                uuid;

    ngx_stream_minecraft_packet_t           *handshake;
    ngx_stream_minecraft_packet_t           *loginstart;

    ngx_chain_t                             *in;
    ngx_chain_t                             *out;
    ngx_chain_t                             *free_chain;
    ngx_chain_t                             *busy_chain;
} ngx_stream_minecraft_forward_ctx_t;

extern ngx_module_t ngx_stream_minecraft_forward_module;

#if (NGX_PCRE)
extern ngx_regex_t *ngx_stream_minecraft_forward_module_srv_hostname_check_regex;
#endif

#endif
