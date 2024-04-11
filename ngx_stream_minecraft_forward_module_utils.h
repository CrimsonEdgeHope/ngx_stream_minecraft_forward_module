#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_UTILS_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_UTILS_H_

ngx_int_t read_minecraft_varint(u_char *buf, size_t *byte_len);

u_char *parse_packet_length(ngx_stream_session_t *s, u_char *bufpos, size_t *varint_byte_len);

u_char *parse_string_from_packet(ngx_pool_t *pool, u_char *bufpos, size_t len);

u_char *create_minecraft_varint(ngx_pool_t *pool, ngx_int_t value, size_t *byte_len);

ngx_int_t ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(ngx_str_t *str);

#define VARINT_MAX_BYTE_LEN 5

#endif
