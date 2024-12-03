#ifndef _NSMFM_UUID_UTILS_
#define _NSMFM_UUID_UTILS_

extern "C"
{
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
}

#include "../protocol/nsmfm_packet.hpp"

class MinecraftUUID {
public:
    u_char literals[_MC_UUID_LITERAL_LEN_ + 1];
    
    static MinecraftUUID* create(u_char *buf);
};

#endif