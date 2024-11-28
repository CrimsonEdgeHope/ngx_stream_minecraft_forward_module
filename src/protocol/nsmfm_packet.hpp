#ifndef _NSMFM_MINECRAFT_PACKET_
#define _NSMFM_MINECRAFT_PACKET_

extern "C"
{
#include <ngx_core.h>
#include <ngx_string.h>
}
#include "nsmfm_varint.hpp"

#define _MC_PORT_LEN_ sizeof(u_short)

#define _MC_UUID_LITERAL_LEN_ 32  // Without dashes.
#define _MC_UUID_BYTE_LEN_ (_MC_UUID_LITERAL_LEN_ / 2)

#define _MC_HANDSHAKE_PACKET_ID_         0x00
#define _MC_HANDSHAKE_STATUS_STATE_      1
#define _MC_HANDSHAKE_LOGINSTART_STATE_  2
#define _MC_HANDSHAKE_TRANSFER_STATE_    3

#define _MC_LOGINSTART_PACKET_ID_  0x00

#define _MC_STATUS_REQUEST_PACKET_ID_   0x00
#define _MC_STATUS_RESPONSE_PACKET_ID_  0x00

class MinecraftString {
public:
    ngx_pool_t      *pool;
    MinecraftVarint  length;
    u_char          *content;

    MinecraftString(ngx_pool_t *pool) {
        this->length = MinecraftVarint::create(0);
        this->pool = pool;
    }

    MinecraftString() : MinecraftString(NULL) {}

    ~MinecraftString() {
        if (pool && content) {
            ngx_pfree(pool, content);
        }
    }

    ngx_int_t determine_length(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
    ngx_int_t determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
};

class MinecraftPacket {
public:
    MinecraftVarint  id;
    MinecraftVarint  length;
    u_char          *content;
    ngx_pool_t      *pool;

    MinecraftPacket(int id, ngx_pool_t *pool) {
        this->length = MinecraftVarint::create(0);
        this->id = MinecraftVarint::create(id);
        this->pool = pool;
        this->content = NULL;
    }

    ~MinecraftPacket() {
        if (pool && content) {
            ngx_pfree(pool, content);
        }
    }

    virtual bool empty() {
        return !content;
    }

    virtual ngx_int_t determine_length(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
    virtual ngx_int_t determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast);
};

class MinecraftHandshake : public MinecraftPacket {
public:
    MinecraftVarint  *protocol_number;
    MinecraftString  *server_address;
    u_short           server_port;
    MinecraftVarint  *next_state;

    MinecraftHandshake(ngx_pool_t *pool) : MinecraftPacket(_MC_HANDSHAKE_PACKET_ID_, pool) {
        this->protocol_number = NULL;
        this->server_address = NULL;
        this->next_state = NULL;
        this->server_port = 0;
    }

    ~MinecraftHandshake() {
        if (protocol_number) {
            protocol_number->~MinecraftVarint();
            delete[] protocol_number;
        }
        if (server_address) {
            server_address->~MinecraftString();
            delete[] server_address;
        }
        if (next_state) {
            next_state->~MinecraftVarint();
            delete[] next_state;
        }
    }

    bool empty() override {
        return !protocol_number || !server_address || !next_state;
    }

    ngx_int_t determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) override;
};

class MinecraftLoginstart : public MinecraftPacket {
public:
    MinecraftString  *username;
    MinecraftString  *uuid;

    MinecraftLoginstart(ngx_pool_t *pool) : MinecraftPacket(_MC_LOGINSTART_PACKET_ID_, pool) {
        this->username = NULL;
        this->uuid = NULL;
    }

    ~MinecraftLoginstart() {
        if (username) {
            username->~MinecraftString();
            delete[] username;
        }
        if (uuid) {
            uuid->~MinecraftString();
            delete[] uuid;
        }
    }

    bool empty() override {
        return !username || !uuid;
    }

    ngx_int_t determine_content(ngx_stream_session_t *s, u_char **bufpos, u_char *buflast) override;
};

#endif
