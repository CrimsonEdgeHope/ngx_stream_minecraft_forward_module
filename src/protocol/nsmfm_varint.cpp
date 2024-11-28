#include "nsmfm_varint.hpp"

int MinecraftVarint::parse(u_char *buf, int *bytes_length) {
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

    if (bytes_length != NULL) {
        *bytes_length = (int)(pos - buf) + 1;
    }

    return value;
}

MinecraftVarint* MinecraftVarint::create(int value) {
    u_char  buf[_MC_VARINT_MAX_BYTE_LEN_];

    int count = 0;

    for (;;) {
        if ((value & ~0x7F) == 0) {
            buf[count++] = value;
            break;
        }

        buf[count++] = ((value & 0x7F) | 0x80);

        value >>= 7;
    }

    return new MinecraftVarint(buf, count);
}
