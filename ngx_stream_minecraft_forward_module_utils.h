#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_UTILS_H
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_UTILS_H

ngx_int_t read_minecraft_varint(u_char *buf, size_t *byte_len);

u_char *parse_packet_length(ngx_stream_session_t *s, u_char *bufpos, size_t *varint_byte_len);

u_char *parse_string_from_packet(ngx_connection_t *c, u_char *bufpos, size_t len);

u_char *create_minecraft_varint(ngx_connection_t *c, ngx_int_t value, size_t *byte_len);

ngx_int_t srv_conf_validate_domain(ngx_str_t *str);

#define VARINT_MAX_BYTE_LEN 5

#endif
