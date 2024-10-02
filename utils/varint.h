#ifndef _NSMFM_VARINT_UTILS_
#define _NSMFM_VARINT_UTILS_

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdbool.h>
#include "../module/session.h"
#include "../protocol/packet.h"

int parse_varint(u_char *buf, int *byte_len);
bool parse_varint_fill_object(u_char *buf, minecraft_varint *var);
int parse_varint_object(minecraft_varint *var, int *byte_len);

void create_varint(int value, u_char *buffer, int *byte_len);
void fill_varint_object(int value, minecraft_varint *res);
minecraft_varint *create_varint_object(int value, ngx_pool_t *pool);

#endif
