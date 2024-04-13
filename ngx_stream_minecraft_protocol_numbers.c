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
        case MINECRAFT_1_18_2:
        case MINECRAFT_1_18_1:
        case MINECRAFT_1_17_1:
        case MINECRAFT_1_17:
        case MINECRAFT_1_16_5:
        case MINECRAFT_1_16_3:
        case MINECRAFT_1_16_2:
        case MINECRAFT_1_16_1:
        case MINECRAFT_1_16:
        case MINECRAFT_1_15_2:
        case MINECRAFT_1_15_1:
        case MINECRAFT_1_15:
        case MINECRAFT_1_14_4:
        case MINECRAFT_1_14_3:
        case MINECRAFT_1_14_2:
        case MINECRAFT_1_14_1:
        case MINECRAFT_1_14:
        case MINECRAFT_1_13_2:
        case MINECRAFT_1_13_1:
        case MINECRAFT_1_13:
        case MINECRAFT_1_12_2:
        case MINECRAFT_1_12_1:
        case MINECRAFT_1_12:
        case MINECRAFT_1_11_2:
        case MINECRAFT_1_11:
        case MINECRAFT_1_10_2:
        case MINECRAFT_1_9_4:
        case MINECRAFT_1_9_2:
        case MINECRAFT_1_9_1:
        case MINECRAFT_1_9:
        case MINECRAFT_1_8_9:
            return NGX_OK;
        default:
            return NGX_ERROR;
    }
}

ngx_int_t is_protocol_num_acceptable_by_ctx(ngx_stream_minecraft_forward_ctx_t *ctx) {
    return is_protocol_num_acceptable(ctx->protocol_num);
}
