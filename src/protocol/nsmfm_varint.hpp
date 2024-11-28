#ifndef _NSMFM_VARINT_UTILS_
#define _NSMFM_VARINT_UTILS_

extern "C"
{
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
}

#define _MC_VARINT_MAX_BYTE_LEN_ 5

class MinecraftVarint {
public:
    u_char bytes[_MC_VARINT_MAX_BYTE_LEN_];
    int    bytes_length : 3;
    
    static int parse(u_char *buf, int *bytes_length);
    static MinecraftVarint create(int value);

    MinecraftVarint(u_char *bytes, int bytes_length) {
        if (bytes) {
            ngx_memcpy(this->bytes, bytes, bytes_length);
        }
        this->bytes_length = bytes_length;
    }

    MinecraftVarint() : MinecraftVarint(NULL, 0) {}
};

#endif
