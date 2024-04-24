#ifndef _NGX_STREAM_MINECRAFT_FORWARD_MODULE_UTILS_H_
#define _NGX_STREAM_MINECRAFT_FORWARD_MODULE_UTILS_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

ngx_int_t read_minecraft_varint(u_char *buf, size_t *byte_len);
u_char *create_minecraft_varint(ngx_pool_t *pool, ngx_int_t value, size_t *byte_len);

u_char *parse_packet_length(ngx_stream_session_t *s, u_char *bufpos, size_t *packet_len, size_t *varint_byte_len);

ngx_int_t ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(ngx_str_t *str);

#define _MC_VARINT_MAX_BYTE_LEN_ 5
#define _MC_PORT_LEN_ 2

#define _MC_UUID_LITERAL_LEN_ 32
#define _MC_UUID_BYTE_LEN_ (_MC_UUID_LITERAL_LEN_ / 2)

#define _MC_HANDSHAKE_STATUS_STATE_ 1
#define _MC_HANDSHAKE_LOGINSTART_STATE_ 2

#endif
