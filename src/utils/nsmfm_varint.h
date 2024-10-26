#ifndef _NSMFM_VARINT_UTILS_
#define _NSMFM_VARINT_UTILS_

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdbool.h>
#include "../protocol/nsmfm_packet.h"

int nsmfm_parse_varint(u_char *buf, int *byte_len);
bool nsmfm_parse_varint_fill_object(u_char *buf, minecraft_varint *var);
int nsmfm_parse_varint_object(minecraft_varint *var, int *byte_len);

void nsmfm_create_varint(int value, u_char *buffer, int *byte_len);
void nsmfm_fill_varint_object(int value, minecraft_varint *res);
minecraft_varint *nsmfm_create_varint_object(int value, ngx_pool_t *pool);

#endif
