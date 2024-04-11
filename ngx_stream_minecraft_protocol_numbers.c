#include "ngx_stream_minecraft_protocol_numbers.h"
#include "ngx_stream_minecraft_forward_module.h"

ngx_int_t is_protocol_num_acceptable(ngx_int_t protocol_num) {
    switch (protocol_num) {
        case MINECRAFT_1_20_4:
        case MINECRAFT_1_20_2:
        case MINECRAFT_1_20_1:
        case MINECRAFT_1_19_4:
        case MINECRAFT_1_19_3:
        case MINECRAFT_1_19_2:
        case MINECRAFT_1_19:
            return NGX_OK;
        default:
            return NGX_ERROR;
    }
}

ngx_int_t is_protocol_num_acceptable_by_ctx(ngx_stream_minecraft_forward_ctx_t *ctx) {
    return is_protocol_num_acceptable(ctx->protocol_num);
}
