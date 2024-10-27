#include <ngx_core.h>
#include <ngx_string.h>
#include <stdbool.h>
#include "nsmfm_packet.h"
#include "../utils/nsmfm_varint.h"

bool nsmfm_init_empty_handshake_packet(minecraft_packet *packet, ngx_pool_t *pool) {
    if (packet == NULL || pool == NULL) {
        return false;
    }
    packet->content = ngx_pnalloc(pool, sizeof(minecraft_handshake));
    if (packet->content == NULL) {
        return false;
    }

    nsmfm_fill_varint_object(_MC_HANDSHAKE_PACKET_ID_, &packet->id);
    ((minecraft_handshake *)packet->content)->server_port = 0;

    return true;
}

bool nsmfm_init_empty_loginstart_packet(minecraft_packet *packet, ngx_pool_t *pool) {
    if (packet == NULL || pool == NULL) {
        return false;
    }
    packet->content = ngx_pnalloc(pool, sizeof(minecraft_loginstart));
    if (packet->content == NULL) {
        return false;
    }
    nsmfm_fill_varint_object(_MC_LOGINSTART_PACKET_ID_, &packet->id);
    return true;
}
