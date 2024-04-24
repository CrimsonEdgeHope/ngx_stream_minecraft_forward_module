#include "ngx_stream_minecraft_forward_module_utils.h"
#include "ngx_stream_minecraft_forward_module.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_regex.h>
#include <ngx_stream.h>

/*
 Reference: https://wiki.vg/index.php?title=Protocol&oldid=7617#VarInt_and_VarLong
*/

/*
 Varint is used a lot in Minecraft packet.
 This function tries to parse varint and return actual integer value.
 Result should be non-negative. In case anything, it would return -1 indicating failure.

 \param *buf       Nginx buffer pointer.
 \param *byte_len  A `size_t` pointer to which the length of varint bytes will be stored. Optional, pass `NULL` if no need.

 \returns Actual int value represented by the varint. If read failure, -1.
*/
ngx_int_t read_minecraft_varint(u_char *buf, size_t *byte_len) {

    if (!buf) {
        return -1;
    }

    ngx_int_t value;
    ngx_int_t position;
    u_char    byte;
    u_char   *pos;

    value = 0;
    position = 0;

    pos = buf;

    for (;;) {
        byte = *pos;
        value |= (byte & 0x7F) << position;

        if ((byte & 0x80) == 0) {
            break;
        }

        position += 7;

        if (position >= 32) {
            value = -1;
            break;
        }

        ++pos;
    }

    if (value < 0) {
        return -1;
    }

    if (byte_len != NULL) {
        *byte_len = pos - buf + 1;
    }
    return value;
}


/*
 Modern Minecraft Java protocol packet has a preceding varint that indicates the whole packet's length (not including varint bytes themselves, which's often confusing).
 This function parses varint and retrieve actual packet length, to instruct the proxy to expect a fully transmitted packet before prereading and filtering.

 \param *s                Nginx stream session object pointer.
 \param *bufpos           Nginx buffer pointer.
 \param *varint_byte_len  A `size_t` pointer to which the length of varint bytes will be stored. Optional, pass `NULL` if no need.

 \returns Nginx buffer pointer that passes over the parsed varint bytes. If failure, NULL.
*/
u_char *parse_packet_length(ngx_stream_session_t *s, u_char *bufpos, size_t *varint_byte_len) {

    size_t                              vl;
    size_t                              packet_len;
    ngx_stream_minecraft_forward_ctx_t *ctx;

    if (s == NULL) {
        return NULL;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_minecraft_forward_module);

    if (ctx == NULL || bufpos == NULL) {
        return NULL;
    }

    packet_len = read_minecraft_varint(bufpos, &vl);

    if (packet_len <= 0) {
#if (NGX_DEBUG)
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "Read varint, get: %d", packet_len);
#endif
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0, "Unexpected varint value (%d)", packet_len);
        return NULL;
    }
    ctx->expected_packet_len = packet_len;

    if (varint_byte_len != NULL) {
        *varint_byte_len = vl;
    }

    return bufpos + vl;
}


/*
 String follows varint. Retrieve a string and store in an unsigned char array.
 The char array's memory is allocated from the nginx connection object's memory pool.

 \param *pool    Nginx memory pool pointer.
 \param *bufpos  Nginx buffer pointer.
 \param len      String length.

 \returns Pointer to an unsigned char array that stores string. If failure, NULL.
*/
u_char *parse_string_from_packet(ngx_pool_t *pool, u_char *bufpos, size_t len) {
    if (pool == NULL || bufpos == NULL) {
        return NULL;
    }

    u_char *rs;

    rs = ngx_pcalloc(pool, (len + 1) * sizeof(u_char));
    if (rs == NULL) {
        return NULL;
    }

    ngx_memcpy(rs, bufpos, len);
    rs[len] = '\0';
    return rs;
}


/*
 Convert an integer value to varint bytes and store in an unsigned char array.
 The char array's memory is allocated from the nginx connection object's memory pool.

 \param *pool      Nginx memory pool pointer.
 \param value      Integer to be converted. Must be non-negative.
 \param *byte_len  A `size_t` pointer to which the length of varint bytes will be stored. Optional, pass `NULL` if no need.

 \returns Pointer to an unsigned char array that stores varint. If failure, NULL.
*/
u_char *create_minecraft_varint(ngx_pool_t *pool, ngx_int_t value, size_t *byte_len) {

    if (pool == NULL || value < 0) {
        return NULL;
    }

    u_char    *varint;
    ngx_uint_t v;
    ngx_uint_t count;

    v = value;

    varint = ngx_pcalloc(pool, sizeof(u_char) * _MC_VARINT_MAX_BYTE_LEN_);
    if (varint == NULL) {
        return NULL;
    }

    count = 0;

    for (;;) {
        if ((v & ~0x7F) == 0) {
            varint[count++] = v;
            break;
        }

        varint[count++] = ((v & 0x7F) | 0x80);

        v >>= 7;
    }

    if (byte_len != NULL) {
        *byte_len = count;
    }
    return varint;
}

ngx_int_t ngx_stream_minecraft_forward_module_srv_conf_validate_hostname(ngx_str_t *str) {
    if (!str) {
        return NGX_ERROR;
    }
    if (!str->data || str->len > 253 || str->len <= 0) {
        return NGX_ERROR;
    }

#if (NGX_PCRE)
    if (!ngx_stream_minecraft_forward_module_srv_hostname_check_regex) {
        return NGX_OK;
    }
    return ngx_regex_exec(ngx_stream_minecraft_forward_module_srv_hostname_check_regex, str, NULL, 0) >= 0
               ? NGX_OK
               : NGX_ERROR;
#else
    return NGX_OK;
#endif
}
