#ifndef _NSMFM_MINECRAFT_PACKET_
#define _NSMFM_MINECRAFT_PACKET_

#include <ngx_core.h>
#include <ngx_string.h>
#include <stdbool.h>

#define _MC_VARINT_MAX_BYTE_LEN_ 5
#define _MC_PORT_LEN_ sizeof(u_short)

#define _MC_UUID_LITERAL_LEN_ 32
#define _MC_UUID_BYTE_LEN_ (_MC_UUID_LITERAL_LEN_ / 2)

#define _MC_HANDSHAKE_STATUS_STATE_ 1
#define _MC_HANDSHAKE_LOGINSTART_STATE_ 2
#define _MC_HANDSHAKE_TRANSFER_STATE_ 3

typedef struct {
    u_char  bytes[_MC_VARINT_MAX_BYTE_LEN_];
    int     byte_len;
    int     num;
} minecraft_varint;

typedef struct {
    minecraft_varint  len;
    u_char           *content;
} minecraft_string;
typedef u_char            minecraft_uuid[_MC_UUID_LITERAL_LEN_ + 1];

typedef struct minecraft_packet {
    minecraft_varint  length;
    minecraft_varint  id;
    void             *content;
} minecraft_packet;

typedef struct {
    minecraft_varint  protocol_number;
    minecraft_string  server_address;
    u_short           server_port;
    minecraft_varint  next_state;
} minecraft_handshake;

typedef bool (*nsmfm_packet_init)(struct minecraft_packet *packet, ngx_pool_t *pool);

bool nsmfm_handshake_packet_init(minecraft_packet *packet, ngx_pool_t *pool);

typedef struct {
    minecraft_string  username;
    minecraft_uuid    uuid;
} minecraft_loginstart;

bool nsmfm_loginstart_packet_init(minecraft_packet *packet, ngx_pool_t *pool);

#endif
