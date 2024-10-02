#include <ngx_core.h>
#include <ngx_string.h>
#include <stdbool.h>
#include "./packet.h"
#include "../utils/varint.h"

bool nsmfm_handshake_packet_init(minecraft_packet *packet, ngx_pool_t *pool) {
    if (packet == NULL || pool == NULL) {
        return false;
    }
    packet->content = ngx_pnalloc(pool, sizeof(minecraft_handshake));
    if (packet->content == NULL) {
        return false;
    }
    fill_varint_object(0, &packet->id);
    return true;
}

bool nsmfm_loginstart_packet_init(minecraft_packet *packet, ngx_pool_t *pool) {
    if (packet == NULL || pool == NULL) {
        return false;
    }
    packet->content = ngx_pnalloc(pool, sizeof(minecraft_loginstart));
    if (packet->content == NULL) {
        return false;
    }
    fill_varint_object(0, &packet->id);
    return true;
}
