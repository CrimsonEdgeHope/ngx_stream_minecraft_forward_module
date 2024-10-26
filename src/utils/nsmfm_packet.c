#include <ngx_core.h>
#include <ngx_string.h>
#include "../protocol/nsmfm_packet.h"
#include "nsmfm_varint.h"
#include "nsmfm_packet.h"

ngx_int_t nsmfm_get_packet_length(minecraft_packet *packet, u_char **bufpos, u_char *buflast, int *byte_len) {
    if (packet == NULL || bufpos == NULL || buflast == NULL || byte_len == NULL) {
        return NGX_ERROR;
    }
    if (*bufpos == NULL) {
        return NGX_ERROR;
    }

    ngx_int_t  var;

    if (packet->length.num <= 0) {
        var = nsmfm_parse_varint(*bufpos, byte_len);
        if (var <= 0) {
            if (buflast - *bufpos < _MC_VARINT_MAX_BYTE_LEN_) {
                return NGX_AGAIN;
            }
            return NGX_ERROR;
        }

        packet->length.num = var;
        ngx_memcpy(packet->length.bytes, *bufpos, *byte_len);
        packet->length.byte_len = *byte_len;
    }

    (*bufpos) += *byte_len;

    return NGX_OK;
}

ngx_int_t nsmfm_receive_packet(minecraft_packet *packet, u_char *bufpos, u_char *buflast, nsmfm_packet_init init, ngx_pool_t *pool) {
    if (packet == NULL || bufpos == NULL || buflast == NULL) {
        return NGX_ERROR;
    }
    if (bufpos == NULL) {
        return NGX_ERROR;
    }
    if (buflast - bufpos < (ssize_t)packet->length.num) {
        return NGX_AGAIN;
    }
    if (init != NULL) {
        if (!init(packet, pool)) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

ngx_int_t nsmfm_get_string(u_char **bufpos, minecraft_string *str, ngx_pool_t *pool) {
    if (bufpos == NULL || str == NULL || pool == NULL) {
        return NGX_ERROR;
    }
    if (*bufpos == NULL) {
        return NGX_ERROR;
    }

    if (!nsmfm_parse_varint_fill_object(*bufpos, &str->len)) {
        return NGX_ERROR;
    }

    str->content = ngx_pnalloc(pool, sizeof(u_char) * (str->len.num + 1));
    if (!str->content) {
        return NGX_ERROR;
    }
    str->content[str->len.num] = 0;

    ngx_memcpy(str->content, (*bufpos) + str->len.byte_len, str->len.num);
    (*bufpos) += str->len.byte_len + str->len.num;

    return NGX_OK;
}
