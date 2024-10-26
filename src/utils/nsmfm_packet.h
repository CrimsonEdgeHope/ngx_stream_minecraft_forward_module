#ifndef _NSMFM_PACKET_UTILS_
#define _NSMFM_PACKET_UTILS_

#include <ngx_core.h>
#include "../protocol/nsmfm_packet.h"

ngx_int_t nsmfm_get_packet_length(minecraft_packet *packet, u_char **bufpos, u_char *buflast, int *byte_len);
ngx_int_t nsmfm_receive_packet(minecraft_packet *packet, u_char *bufpos, u_char *buflast, nsmfm_packet_init init, ngx_pool_t *pool);
ngx_int_t nsmfm_get_string(u_char **bufpos, minecraft_string *str, ngx_pool_t *pool);

#endif
