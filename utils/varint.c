#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_regex.h>
#include <ngx_stream.h>
#include "./varint.h"
#include "../module/session.h"

/*
 Reference: https://wiki.vg/index.php?title=Protocol&oldid=7617#VarInt_and_VarLong
*/

/*
 Parse varint and return actual integer value.
 Result should be non-negative. In case anything, it would return `-1` indicating failure.

 \param *buf       Buffer pointer.
 \param *byte_len  Optional. `int` pointer that stores length of the varint bytes.

 \returns Actual `int` value represented by the varint. If failure, `-1`.
*/
int parse_varint(u_char *buf, int *byte_len) {
    if (buf == NULL) {
        return -1;
    }

    int      value;
    int      position;
    u_char   byte;
    u_char  *pos;

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

        pos++;
    }

    if (value < 0) {
        return -1;
    }

    if (byte_len != NULL) {
        *byte_len = (int)(pos - buf) + 1;
    }

    return value;
}

bool parse_varint_fill_object(u_char *buf, minecraft_varint *var) {
    if (var == NULL) {
        return false;
    }
    int res;
    res = parse_varint(buf, &var->byte_len);
    if (res == -1) {
        return false;
    }
    var->num = res;
    ngx_memcpy(var->bytes, buf, var->byte_len);
    return true;
}

/*
 \param *var       `minecraft_varint` object pointer.
 \param *byte_len  Optional. `int` pointer that stores length of the varint bytes.

 \returns Actual `int` value represented by the varint. If failure, `-1`.
*/
int parse_varint_object(minecraft_varint *var, int *byte_len) {
    if (var == NULL) {
        return -1;
    }

    return parse_varint(var->bytes, byte_len);
}

void create_varint(int value, u_char *buffer, int *byte_len) {
    int count = 0;

    for (;;) {
        if ((value & ~0x7F) == 0) {
            buffer[count++] = value;
            break;
        }

        buffer[count++] = ((value & 0x7F) | 0x80);

        value >>= 7;
    }

    if (byte_len != NULL) {
        *byte_len = count;
    }
}

void fill_varint_object(int value, minecraft_varint *res) {
    if (value < 0 || res == NULL) {
        return;
    }

    create_varint(value, res->bytes, &res->byte_len);
    res->num = value;
}

/*
 Convert an integer value to varint bytes and store in an unsigned char array.
 The char array's memory is allocated from the nginx connection object's memory pool.

 \param value  Integer to be converted. Must be non-negative.
 \param *pool  Nginx memory pool object pointer.

 \returns `minecraft_varint` object pointer. If failure, `NULL`.
*/
minecraft_varint *create_varint_object(int value, ngx_pool_t *pool) {
    if (value < 0 || pool == NULL) {
        return NULL;
    }

    minecraft_varint  *res;

    res = ngx_pnalloc(pool, sizeof(minecraft_varint));
    if (res == NULL) {
        return NULL;
    }

    fill_varint_object(value, res);

    return res;
}
